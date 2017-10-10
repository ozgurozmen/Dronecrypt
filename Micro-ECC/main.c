
/* Includes ------------------------------------------------------------------*/
#include "stm32f4_discovery.h"
#include <stdio.h>
#include "uECC.h"

/* Private typedef -----------------------------------------------------------*/
GPIO_InitTypeDef  GPIO_InitStructure;
USART_InitTypeDef USART_InitStructure;
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
void LED_config(void);
void USART_Configuration(void);
int putcharx(int ch);
/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Main program
  * @param  None
  * @retval None
  */

static unsigned int *DWT_CYCCNT = (unsigned int*)0xE0001004;
static unsigned int *DWT_CTRL = (unsigned int*)0xE0001000;
static unsigned int *SCB_DEMCR = (unsigned int*)0xE000EDFC;

// Benchmark and test parameters  
#define BENCH_LOOPS       10       // Number of iterations per bench
#define TEST_LOOPS        10       // Number of iterations per test

#define cpucycles() (*DWT_CYCCNT);
#define uECC_ASM uECC_asm_fast;

static uint32_t g_rand = 88172645463325252ull;
int fake_rng(uint8_t *dest, unsigned size) {
    while (size) {
        g_rand ^= (g_rand << 13);
        g_rand ^= (g_rand >> 7);
        g_rand ^= (g_rand << 17);

        unsigned amount = (size > 8 ? 8 : size);
        memcpy(dest, &g_rand, amount);
        dest += amount;
        size -= amount;
    }
    return 1;
}

int main(void)
{
    *SCB_DEMCR = *SCB_DEMCR | 0x01000000;
    *DWT_CYCCNT = 0;             // reset the counter
    *DWT_CTRL = *DWT_CTRL | 1 ;  // enable the counter
    int i, c;
    uint8_t private[32] = {0};
    uint8_t secret1[32] = {0};
    uint8_t public[64] = {0};
    uint8_t private2[32] = {0};
    uint8_t public2[64] = {0};
    
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};
    uECC_set_rng(&fake_rng);
    unsigned int cycles, cycles1, cycles2;
    int n;
    const struct uECC_Curve_t * curves[5];
    int num_curves = 0;
#if uECC_SUPPORTS_secp256k1
    curves[num_curves++] = uECC_secp256k1();
#endif
    printf("Curve = secp256k1 32 byte message\n");
    printf("Benchmarking microECC\n");
    uECC_make_key(public2, private2, curves[c]);
    c = 0;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        if (!uECC_make_key(public, private, curves[c])) {
            printf("uECC_make_key() failed\n");
            //return 1;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    
    cycles = cycles/BENCH_LOOPS;
    printf("  microECC's key generation runs in ...... %d \n", cycles);
    cycles = 0;
    
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        int r = uECC_shared_secret(public2, private, secret1, curves[c]);
        if (!r) {
            printf("shared_secret() failed (1)\n");
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    
    cycles = cycles/BENCH_LOOPS;
    printf("  microECC's ECDH runs in ...... %d \n", cycles);
    cycles = 0;
    
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        if (!uECC_make_key(public, private, curves[c])) {
            printf("uECC_make_key() failed\n");
            //return 1;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    
    cycles = cycles/BENCH_LOOPS;
    printf("  microECC's key generation runs in ...... %d \n", cycles);
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        if (!uECC_sign(private, hash, sizeof(hash), sig, curves[c])) {
            printf("uECC_make_key() failed\n");
            //return 1;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  microECC's signing runs in ...... %d \n", cycles/BENCH_LOOPS);
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        if (!uECC_verify(public, hash, sizeof(hash), sig, curves[c])) {
            printf("uECC_make_key() failed\n");
            //return 1;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  microECC's verification runs in ...... %d \n", cycles/BENCH_LOOPS);
    cycles = 0;
    
    
    
    
    
//    for (i = 0; i < 10; ++i) {
//        printf(".");
//        
//        if (!uECC_make_key(public, private, curves[c])) {
//            printf("uECC_make_key() failed\n");
//            //return 1;
//        }
//        //memcpy(hash, public, sizeof(hash));
//        
//        if (!uECC_sign(private, hash, sizeof(hash), sig, curves[c])) {
//            printf("uECC_sign() failed\n");
//            //return 1;
//        }
//
//        if (!uECC_verify(public, hash, sizeof(hash), sig, curves[c])) {
//            printf("uECC_verify() failed\n");
//            //return 1;
//        }
//    }
       
    
    
    return 0;
}








/**
  * @brief  LED Configuration function
  * @param  None
  * @retval None
  */
void LED_config(void)
{
  /* GPIOD Periph clock enable */
  RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOD, ENABLE);

  /* Configure PD12, PD13, PD14 and PD15 in output pushpull mode */
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_12 | GPIO_Pin_13| GPIO_Pin_14| GPIO_Pin_15;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_OUT;
  GPIO_InitStructure.GPIO_OType = GPIO_OType_PP;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_100MHz;
  GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_NOPULL;
  GPIO_Init(GPIOD, &GPIO_InitStructure);
  
}

/**
  * @brief  USART Configuration function
  * @param  None
  * @retval None
  */
void USART_Configuration(void){
        // sort out clocks
        RCC_AHB1PeriphClockCmd( RCC_AHB1Periph_GPIOA, ENABLE);
        RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART2, ENABLE);
         /* Configure USART2 Tx (PA.02) as alternate function push-pull */
        GPIO_InitStructure.GPIO_Pin = GPIO_Pin_2;
        GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
        GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;
        GPIO_InitStructure.GPIO_OType = GPIO_OType_PP;
        GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_UP;
        GPIO_Init(GPIOA, &GPIO_InitStructure);
        // Map USART2 to A.02
        GPIO_PinAFConfig(GPIOA, GPIO_PinSource2, GPIO_AF_USART2);
        // Initialize USART
  	USART_InitStructure.USART_BaudRate = 115200;
  	USART_InitStructure.USART_WordLength = USART_WordLength_8b;
  	USART_InitStructure.USART_StopBits = USART_StopBits_1;
  	USART_InitStructure.USART_Parity = USART_Parity_No;
  	USART_InitStructure.USART_HardwareFlowControl = USART_HardwareFlowControl_None;
  	USART_InitStructure.USART_Mode = USART_Mode_Tx;
	/* Configure USART */
	USART_Init(USART2, &USART_InitStructure);   
	  /* Enable the USART */
	USART_Cmd(USART2, ENABLE);	
}

/**
  * @brief  Function that printf uses to push characters to serial port
  * @param  ch: ascii character 
  * @retval character
  */
int putcharx(int ch)
{
  while (USART_GetFlagStatus(USART2, USART_FLAG_TXE) == RESET);
  USART_SendData(USART2, (uint8_t)ch);
  return ch; 
} 




#ifdef  USE_FULL_ASSERT

/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t* file, uint32_t line)
{
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  while (1)
  {}
}
#endif

/**
  * @}
  */ 

/**
  * @}
  */ 

