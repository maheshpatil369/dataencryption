#include <Arduino.h>
#include <Wire.h>
#include <Servo.h>
#include <Adafruit_PWMServoDriver.h>

#include <stm32f1xx_hal.h>

#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>

#define UART_BAUDRATE 1000000

// USART2
// TX = PA2
// RX = PA3

// COMMAND:
//
// A3,90,45,30,20,1500,01,00,F3\r\n
//
// A3       = Header
// 90       = Servo 1
// 45       = Servo 2
// 30       = Servo 3
// 20       = Servo 4
// 1500     = Thruster
// 01       = Relay 1
// 00       = Relay 2
// F3       = Footer


#define PKT_HEADER 0xA3
#define PKT_END    0xF3
#define PKT_LEN    10

#define SERVO_FIELD_FIRST_INDEX 1
#define SERVO_FIELD_LAST_INDEX  4

#define THRUSTER_FIELD_INDEX 5
#define RELAY1_FIELD_INDEX   7
#define RELAY2_FIELD_INDEX   8

#define ACK_BYTE 0x06
#define NAK_BYTE 0x15


#define TELEMETRY_PERIOD_MS 10       // 100 Hz


#define CMD_BUFFER_SIZE 512

char cmdBuffer[CMD_BUFFER_SIZE];

uint16_t cmdIndex = 0;


UART_HandleTypeDef huart2;


Adafruit_PWMServoDriver pwm =
    Adafruit_PWMServoDriver(0x40);

#define SERVO_MIN 150
#define SERVO_MAX 600

#define SERVO_ANGLE_MIN 45
#define SERVO_ANGLE_MAX 180

const uint8_t servoChannels[4] =
{
    12,
    13,
    14,
    15
};


volatile uint8_t Servo1Pos = 90;
volatile uint8_t Servo2Pos = 90;
volatile uint8_t Servo3Pos = 90;
volatile uint8_t Servo4Pos = 90;


volatile uint8_t Servo1 = 90;
volatile uint8_t Servo2 = 90;
volatile uint8_t Servo3 = 90;
volatile uint8_t Servo4 = 90;

volatile uint16_t Thruster = 1500;

volatile uint8_t Relay1 = 0;
volatile uint8_t Relay2 = 0;

volatile uint8_t RelayOutput = 0;


#define ESC_PIN PB3

#define THRUSTER_MIN_US  1100
#define THRUSTER_STOP_US 1500
#define THRUSTER_MAX_US  1900

Servo esc;



#define RELAY1_PIN PB12
#define RELAY2_PIN PB13



unsigned long lastTelemetryTime = 0;


char telemetryTxBuffer[128];


#define DEBUG_VERBOSE 0

char debugTxBuffer[128];


void MX_GPIO_Init()
{
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();

    GPIO_InitTypeDef gpio = {0};



    gpio.Pin = GPIO_PIN_2;

    gpio.Mode = GPIO_MODE_AF_PP;

    gpio.Speed = GPIO_SPEED_FREQ_HIGH;

    HAL_GPIO_Init(
        GPIOA,
        &gpio
    );



    gpio.Pin = GPIO_PIN_3;

    gpio.Mode = GPIO_MODE_INPUT;

    gpio.Pull = GPIO_NOPULL;

    HAL_GPIO_Init(
        GPIOA,
        &gpio
    );



    gpio.Pin = GPIO_PIN_12;

    gpio.Mode = GPIO_MODE_OUTPUT_PP;

    gpio.Speed = GPIO_SPEED_FREQ_LOW;

    HAL_GPIO_Init(
        GPIOB,
        &gpio
    );

    HAL_GPIO_WritePin(
        GPIOB,
        GPIO_PIN_12,
        GPIO_PIN_RESET
    );

    pinMode(
        RELAY1_PIN,
        OUTPUT
    );

    digitalWrite(
        RELAY1_PIN,
        LOW
    );


    gpio.Pin = GPIO_PIN_13;

    gpio.Mode = GPIO_MODE_OUTPUT_PP;

    gpio.Speed = GPIO_SPEED_FREQ_LOW;

    HAL_GPIO_Init(
        GPIOB,
        &gpio
    );

    HAL_GPIO_WritePin(
        GPIOB,
        GPIO_PIN_13,
        GPIO_PIN_RESET
    );

    pinMode(
        RELAY2_PIN,
        OUTPUT
    );

    digitalWrite(
        RELAY2_PIN,
        LOW
    );
}



void MX_USART2_UART_Init()
{
    __HAL_RCC_USART2_CLK_ENABLE();

    huart2.Instance = USART2;

    huart2.Init.BaudRate =
        UART_BAUDRATE;

    huart2.Init.WordLength =
        UART_WORDLENGTH_8B;

    huart2.Init.StopBits =
        UART_STOPBITS_1;

    huart2.Init.Parity =
        UART_PARITY_NONE;

    huart2.Init.Mode =
        UART_MODE_TX_RX;

    huart2.Init.HwFlowCtl =
        UART_HWCONTROL_NONE;

    huart2.Init.OverSampling =
        UART_OVERSAMPLING_16;

    HAL_UART_Init(
        &huart2
    );
}



bool uartTransmit(
    const uint8_t *data,
    uint16_t len
)
{
    if (data == NULL || len == 0)
    {
        return false;
    }

    return
        HAL_UART_Transmit(
            &huart2,
            const_cast<uint8_t *>(data),
            len,
            10
        ) == HAL_OK;
}



bool uartReadByte(
    uint8_t &receivedByte
)
{


    if ((huart2.Instance->SR &
         USART_SR_RXNE) == 0)
    {
        return false;
    }



    receivedByte =
        static_cast<uint8_t>(
            huart2.Instance->DR & 0xFF
        );

    return true;
}


void debugPrintf(
    const char *format,
    ...
)
{
#if DEBUG_VERBOSE

    if (format == NULL)
    {
        return;
    }

    va_list args;

    va_start(
        args,
        format
    );

    int len =
        vsnprintf(
            debugTxBuffer,
            sizeof(debugTxBuffer),
            format,
            args
        );

    va_end(args);

    if (len > 0)
    {
        if (len >=
            (int)sizeof(debugTxBuffer))
        {
            len =
                sizeof(debugTxBuffer) - 1;
        }

        uartTransmit(
            reinterpret_cast<const uint8_t *>(
                debugTxBuffer
            ),
            static_cast<uint16_t>(len)
        );
    }

#else

    (void)format;

#endif
}



uint16_t angleToPwm(
    uint8_t angle
)
{
    angle =
        constrain(
            angle,
            SERVO_ANGLE_MIN,
            SERVO_ANGLE_MAX
        );

    return map(
        angle,
        0,
        180,
        SERVO_MIN,
        SERVO_MAX
    );
}



bool moveServoOneDegree(
    uint8_t channel,
    volatile uint8_t &currentPosition,
    uint8_t targetPosition
)
{
    uint8_t newPosition =
        currentPosition;


    if (targetPosition >
        currentPosition)
    {
        if (currentPosition <
            SERVO_ANGLE_MAX)
        {
            newPosition =
                currentPosition + 1;
        }
    }

   

    else if (
        targetPosition <
        currentPosition
    )
    {
        if (currentPosition >
            SERVO_ANGLE_MIN)
        {
            newPosition =
                currentPosition - 1;
        }
    }

  

    if (newPosition ==
        currentPosition)
    {
        return true;
    }



    pwm.setPWM(
        channel,
        0,
        angleToPwm(
            newPosition
        )
    );

    currentPosition =
        newPosition;

    return true;
}



bool applyCommandToHardware(
    uint8_t servo1Target,
    uint8_t servo2Target,
    uint8_t servo3Target,
    uint8_t servo4Target,
    uint16_t thrusterValue,
    uint8_t relay1Value,
    uint8_t relay2Value
)
{
    

    if (!moveServoOneDegree(
            servoChannels[0],
            Servo1Pos,
            servo1Target))
    {
        return false;
    }
 

    if (!moveServoOneDegree(
            servoChannels[1],
            Servo2Pos,
            servo2Target))
    {
        return false;
    }


    if (!moveServoOneDegree(
            servoChannels[2],
            Servo3Pos,
            servo3Target))
    {
        return false;
    }

 

    if (!moveServoOneDegree(
            servoChannels[3],
            Servo4Pos,
            servo4Target))
    {
        return false;
    }



    esc.writeMicroseconds(
        thrusterValue
    );



    digitalWrite(
        RELAY1_PIN,
        relay1Value ?
            HIGH :
            LOW
    );



    digitalWrite(
        RELAY2_PIN,
        relay2Value ?
            HIGH :
            LOW
    );



    Servo1 =
        servo1Target;

    Servo2 =
        servo2Target;

    Servo3 =
        servo3Target;

    Servo4 =
        servo4Target;

    Thruster =
        thrusterValue;

    Relay1 =
        relay1Value;

    Relay2 =
        relay2Value;

    RelayOutput =
        (relay1Value == 1 &&
         relay2Value == 0)
            ? 1
            : 0;

    return true;
}



bool parseAndValidatePacket(
    char *str
)
{
    if (str == NULL)
    {
        return false;
    }

    char *token =
        strtok(
            str,
            ","
        );

    int index = 0;

    uint8_t packet[PKT_LEN] =
        {0};

    uint16_t thrusterValue =
        THRUSTER_STOP_US;

    uint8_t relay1Val = 0;
    uint8_t relay2Val = 0;

    bool error = false;

 

    while (token != NULL)
    {
        if (index >= PKT_LEN)
        {
            error = true;
            break;
        }


        if (index == 0 ||
            index == 9)
        {
            char *endPtr = NULL;

            long value =
                strtol(
                    token,
                    &endPtr,
                    16
                );

            if (endPtr == token ||
                *endPtr != '\0')
            {
                error = true;
                break;
            }

            if (value < 0 ||
                value > 255)
            {
                error = true;
                break;
            }

            packet[index++] =
                (uint8_t)value;
        }


        else if (
            index >=
                SERVO_FIELD_FIRST_INDEX &&
            index <=
                SERVO_FIELD_LAST_INDEX
        )
        {
            char *endPtr = NULL;

            long value =
                strtol(
                    token,
                    &endPtr,
                    10
                );

            if (endPtr == token ||
                *endPtr != '\0')
            {
                error = true;
                break;
            }

            if (value < 0 ||
                value > 180)
            {
                error = true;
                break;
            }

            packet[index++] =
                (uint8_t)value;
        }



        else if (
            index ==
            THRUSTER_FIELD_INDEX
        )
        {
            char *endPtr = NULL;

            long value =
                strtol(
                    token,
                    &endPtr,
                    10
                );

            if (endPtr == token ||
                *endPtr != '\0')
            {
                error = true;
                break;
            }

            if (value <
                    THRUSTER_MIN_US ||
                value >
                    THRUSTER_MAX_US)
            {
                error = true;
                break;
            }

            thrusterValue =
                (uint16_t)value;

            // Preserve original field indexing
            index += 2;
        }



        else if (
            index ==
            RELAY1_FIELD_INDEX
        )
        {
            char *endPtr = NULL;

            long value =
                strtol(
                    token,
                    &endPtr,
                    16
                );

            if (endPtr == token ||
                *endPtr != '\0')
            {
                error = true;
                break;
            }

            if (value != 0 &&
                value != 1)
            {
                error = true;
                break;
            }

            relay1Val =
                (uint8_t)value;

            index++;
        }

 

        else if (
            index ==
            RELAY2_FIELD_INDEX
        )
        {
            char *endPtr = NULL;

            long value =
                strtol(
                    token,
                    &endPtr,
                    16
                );

            if (endPtr == token ||
                *endPtr != '\0')
            {
                error = true;
                break;
            }

            if (value != 0 &&
                value != 1)
            {
                error = true;
                break;
            }

            relay2Val =
                (uint8_t)value;

            index++;
        }

        else
        {
            error = true;
            break;
        }

        token =
            strtok(
                NULL,
                ","
            );
    }


    if (error)
    {
        return false;
    }

    if (index != PKT_LEN)
    {
        return false;
    }


    if (packet[0] != PKT_HEADER)
    {
        return false;
    }



    if (packet[PKT_LEN - 1] != PKT_END)
    {
        return false;
    }


    if (packet[1] > 180 ||
        packet[2] > 180 ||
        packet[3] > 180 ||
        packet[4] > 180)
    {
        return false;
    }



    return applyCommandToHardware(
        packet[1],
        packet[2],
        packet[3],
        packet[4],
        thrusterValue,
        relay1Val,
        relay2Val
    );
}


void processUartRx()
{
    uint8_t ch;

  
    while (uartReadByte(ch))
    {
        

        if (ch == '\r' ||
            ch == '\n')
        {
            if (cmdIndex > 0)
            {
          

                cmdBuffer[cmdIndex] =
                    '\0';


                char receivedCmd[CMD_BUFFER_SIZE];

                memcpy(
                    receivedCmd,
                    cmdBuffer,
                    cmdIndex + 1
                );


                memset(
                    cmdBuffer,
                    0,
                    sizeof(cmdBuffer)
                );

                cmdIndex = 0;

   

                if (strcasecmp(
                        receivedCmd,
                        "PING"
                    ) == 0)
                {
                    static const uint8_t pong[] =
                        "PONG\r\n";

                    uartTransmit(
                        pong,
                        sizeof(pong) - 1
                    );
                }

             

                else
                {
                    bool valid =
                        parseAndValidatePacket(
                            receivedCmd
                        );

                    if (!valid)
                    {
                        static const uint8_t nak =
                            NAK_BYTE;

                        uartTransmit(
                            &nak,
                            1
                        );
                    }
                }

      

                memset(
                    receivedCmd,
                    0,
                    sizeof(receivedCmd)
                );
            }
        }

    

        else
        {
            if (cmdIndex <
                CMD_BUFFER_SIZE - 1)
            {
                cmdBuffer[cmdIndex++] =
                    ch;
            }

    

            else
            {
                memset(
                    cmdBuffer,
                    0,
                    sizeof(cmdBuffer)
                );

                cmdIndex = 0;

#if DEBUG_VERBOSE

                debugPrintf(
                    "[WARN] Command buffer overflow\r\n"
                );

#endif
            }
        }
    }
}



void sendTelemetry(
    uint8_t s1,
    uint8_t s2,
    uint8_t s3,
    uint8_t s4,
    uint16_t thruster,
    uint8_t relay1,
    uint8_t relay2,
    uint8_t relayOutput
)
{
    int len =
        snprintf(
            telemetryTxBuffer,
            sizeof(telemetryTxBuffer),

            "A3,%u,%u,%u,%u,%u,%u,%u,%u,F3\r\n",

            static_cast<unsigned int>(s1),
            static_cast<unsigned int>(s2),
            static_cast<unsigned int>(s3),
            static_cast<unsigned int>(s4),

            static_cast<unsigned int>(thruster),

            static_cast<unsigned int>(relay1),
            static_cast<unsigned int>(relay2),

            static_cast<unsigned int>(relayOutput)
        );

    if (len <= 0)
    {
        return;
    }

    if (len >=
        (int)sizeof(telemetryTxBuffer))
    {
        len =
            sizeof(telemetryTxBuffer) - 1;
    }

    uartTransmit(
        reinterpret_cast<const uint8_t *>(
            telemetryTxBuffer
        ),
        static_cast<uint16_t>(len)
    );
}



void processTelemetry()
{
    unsigned long now =
        millis();



    if ((now -
         lastTelemetryTime) <
        TELEMETRY_PERIOD_MS)
    {
        return;
    }

    lastTelemetryTime =
        now;

   

    uint8_t s1 =
        Servo1Pos;

    uint8_t s2 =
        Servo2Pos;

    uint8_t s3 =
        Servo3Pos;

    uint8_t s4 =
        Servo4Pos;

    uint16_t thrusterVal =
        Thruster;

    uint8_t r1 =
        Relay1;

    uint8_t r2 =
        Relay2;

    uint8_t output =
        RelayOutput;



    sendTelemetry(
        s1,
        s2,
        s3,
        s4,
        thrusterVal,
        r1,
        r2,
        output
    );
}



void SystemClock_Config()
{
    RCC_OscInitTypeDef RCC_OscInitStruct =
        {0};

    RCC_ClkInitTypeDef RCC_ClkInitStruct =
        {0};

    __HAL_RCC_AFIO_CLK_ENABLE();
    __HAL_RCC_PWR_CLK_ENABLE();



    RCC_OscInitStruct.OscillatorType =
        RCC_OSCILLATORTYPE_HSE;

    RCC_OscInitStruct.HSEState =
        RCC_HSE_ON;

    RCC_OscInitStruct.HSEPredivValue =
        RCC_HSE_PREDIV_DIV1;

    RCC_OscInitStruct.HSIState =
        RCC_HSI_ON;



    RCC_OscInitStruct.PLL.PLLState =
        RCC_PLL_ON;

    RCC_OscInitStruct.PLL.PLLSource =
        RCC_PLLSOURCE_HSE;

    RCC_OscInitStruct.PLL.PLLMUL =
        RCC_PLL_MUL9;

    if (HAL_RCC_OscConfig(
            &RCC_OscInitStruct)
        != HAL_OK)
    {
        while (1)
        {
        }
    }



    RCC_ClkInitStruct.ClockType =
        RCC_CLOCKTYPE_HCLK |
        RCC_CLOCKTYPE_SYSCLK |
        RCC_CLOCKTYPE_PCLK1 |
        RCC_CLOCKTYPE_PCLK2;

    RCC_ClkInitStruct.SYSCLKSource =
        RCC_SYSCLKSOURCE_PLLCLK;

    RCC_ClkInitStruct.AHBCLKDivider =
        RCC_SYSCLK_DIV1;

    RCC_ClkInitStruct.APB1CLKDivider =
        RCC_HCLK_DIV2;

    RCC_ClkInitStruct.APB2CLKDivider =
        RCC_HCLK_DIV1;

    if (HAL_RCC_ClockConfig(
            &RCC_ClkInitStruct,
            FLASH_LATENCY_2)
        != HAL_OK)
    {
        while (1)
        {
        }
    }
}



void setup()
{
    

    HAL_Init();

    SystemClock_Config();

    MX_GPIO_Init();

    MX_USART2_UART_Init();

    Wire.begin();

    pwm.begin();

    pwm.setPWMFreq(
        50
    );

    pwm.setOscillatorFrequency(
        27000000
    );

    HAL_Delay(100);


    pwm.setPWM(
        12,
        0,
        angleToPwm(90)
    );

    pwm.setPWM(
        13,
        0,
        angleToPwm(90)
    );

    pwm.setPWM(
        14,
        0,
        angleToPwm(90)
    );

    pwm.setPWM(
        15,
        0,
        angleToPwm(90)
    );

    Servo1Pos = 90;
    Servo2Pos = 90;
    Servo3Pos = 90;
    Servo4Pos = 90;


    esc.attach(
        ESC_PIN,
        THRUSTER_MIN_US,
        THRUSTER_MAX_US
    );

    // Start at neutral
    esc.writeMicroseconds(
        THRUSTER_STOP_US
    );

    Thruster =
        THRUSTER_STOP_US;


    digitalWrite(
        RELAY1_PIN,
        LOW
    );

    digitalWrite(
        RELAY2_PIN,
        LOW
    );

    Relay1 = 0;
    Relay2 = 0;
    RelayOutput = 0;

    lastTelemetryTime =
        millis();

#if DEBUG_VERBOSE

    debugPrintf(
        "\r\n"
        "========================================\r\n"
        " SYSTEM READY\r\n"
        " UART2 = 1 Mbps\r\n"
        " RTOS  = OFF\r\n"
        " DMA   = OFF\r\n"
        " WDT   = OFF\r\n"
        " TELEMETRY = 100 Hz\r\n"
        "========================================\r\n"
    );

#endif

}

void loop()
{

    processUartRx();

    processTelemetry();

 
}