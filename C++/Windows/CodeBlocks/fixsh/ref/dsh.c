/*******************************************************************************
 * dsh.c
 *
 * Copyright (C) 2011-2013 ZheJiang Dahua Technology CO.,LTD.
 *
 * Author : kang_guolian <kang_guolian@dahuatech.com>
 * Version: V1.0.0  Create
 *
 * Description: 
 *
 *       1.
 *       2.
 *
 *       3. 
 *          
 *       4.
 *       5. 
 *
 * Modification: 
 *    Date    :  
 *    Revision:
 *    Author  :
 *    Contents:
 *******************************************************************************/
/* =========================================================================== */
/*                             头文件定义区                                    */
/* =========================================================================== */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/times.h>
#include <time.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/fd.h>
#include "SecondVerify.h"

/* ========================================================================== */
/*                           类型定义区                                                 */
/* ========================================================================== */
typedef unsigned char      Bool;        /* 通用布尔类型 */
typedef int                Int32;       /* 有符号32位整形数类型 */ 
typedef short              Int16;       /* 有符号16位整形数类型 */ 
typedef char               Int8;        /* 有符号8位整形数类型 */ 
typedef void *             Ptr;         /* 指针类型 */
typedef char *             String;      /* 字符串类型，以NUL结尾。*/
typedef char               Char;        /* 字符类型 */
typedef unsigned char      Uchar;       /* 无符号字符类型 */
typedef unsigned int       Uint32;      /* 无符号32位整形数类型 */ 
typedef unsigned short     Uint16;      /* 无符号16位整形数类型 */
typedef unsigned char      Uint8;       /* 无符号8位整形数类型 */ 
/* ========================================================================== */
/*                       宏定义区                                             */
/* ========================================================================== */
#define MAX_BUF_LEN          200
#define MAX_CMD_LEN          30
#define MAX_CMD_CNT          4
#define MAX_URL_LEN          1024
#define O_BLOCK              0x00000800
#define MAX_TRY_TIMES        6
#define SECONDS_OF_DAY       86400
#define SECONDS_OF_HOUR      3600
#define SECONDS_OF_HALFHOUR  1800
#define MAX_BUILTIN_CMD      4
#define FILE_NAME            "/var/tmp/cmd"
#define PROC_UPTIME          "/proc/uptime"
#if defined(FT2004)
#define DEFAULT_IFNAME       "vlan1"
#else
#define DEFAULT_IFNAME       "eth0"
#endif
#define QRCODE               "qr  "
#define SOK                  0     
#define EFAIL                -1        
#define ETIMEOUT             -2        
     
/* ========================================================================== */
/*                     结构体定义区                                           */
/* ========================================================================== */
struct builtincmd {
	const char *name;
	Int32 (*builtin)(int, Char **) ;
};

/* ========================================================================== */
/*                      全局变量区                                            */
/* ========================================================================== */
static String  cmds[MAX_CMD_CNT] = {"shell","help","getDateInfo","diagnose"}; //It will be inited if use config file at hight version
static Int32   cmdCnt  =  0;
static Int32   sh_pid  =  0;
static Int32   old_forcePid;//old  forceground pid
static Int32   pgid_flg = 0;
static Int32 getDateInfocmd(Int32 , Char **) ;
static Int32 shellcmd(Int32, Char **) ;
static Int32 diagnosecmd(Int32, Char **) ;
static Int32 helpcmd(Int32, Char **) ;
static Bool checkProcAnstor(pid_t pid, const char *ancestorName);
static const struct builtincmd builtintab[MAX_BUILTIN_CMD] = {
	{ "diagnose" ,    diagnosecmd  },
	{ "getDateInfo" , getDateInfocmd },
	{ "help"    ,     helpcmd    },    
    { "shell" ,       shellcmd},
};
extern char **environ;
/* ========================================================================== */
/*                      函数定义区                                            */
/* ========================================================================== */
/*******************************************************************************
* 函数名  : diagnosecmd
* 描  述  : 设备诊断命令
* 输  入  : unused param
* 输  出  : 无
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
static Int32 diagnosecmd(Int32 dargc , Char **dargv)
{
	Int32 ret = 0;
    if ((dargc==2) && (dargv[1][0] > 0x30) && (dargv[1][0] < 0x38) )
    {
		switch(dargv[1][0])        
        {
			case 0x31:
				ret = system("cat /proc/interrupts");
				break;
			case 0x32: 
				ret = system("cat /proc/meminfo");
				break;
			case 0x33: 
				ret = system("cat /proc/devices");
				break;
			case 0x34:  
				ret = system("cat /proc/net/dev");
				break;
			case 0x35: 
				ret = system("cat /proc/uptime");
				break;
			case 0x36:
				ret = system("route -n");
				break;
			
			default:
				break;
           
        }
     }
    else
    {
        printf("USAGE:\n");
        printf("diagnose [object]\n");
        printf("object: default [1]\n");
        printf("        1:   cat /proc/interrupts\n");
        printf("        2:   cat /proc/meminfo\n");
        printf("        3:   cat /proc/devices\n");
        printf("        4:   cat /proc/net/dev\n");
        printf("        5:   cat /proc/uptime\n");
        printf("        6:   route -n\n");
        return EFAIL;
    }
	
	if (-1 == ret)
	{
		printf("Not support try help\n");
	}
   return SOK; 
}
/*******************************************************************************
* 函数名  : getDateInfocmd
* 描  述  : 获取时间日期
* 输  入  : unsued param
* 输  出  : 无
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
static Int32 getDateInfocmd(Int32 argc , Char **argv )
{
    String wday[] = {(char *)"Sun",(char *)"Mon",(char *)"Tue",(char *)"Wed",
                    (char *)"Thu",(char *)"Fri",(char *)"Sat"};
    String mon[]  = {(char *)"Jan",(char *)"Feb",(char *)"Mar",(char *)"Apr",
                    (char *)"May",(char *)"Jun",(char *)"Jul",(char *)"Aug",
                    (char *)"Sep",(char *)"Oct",(char *)"Nov",(char *)"Dec"};
    struct tm *ptr = NULL;
    time_t It;

    It  = time(&It);
    ptr = localtime(&It);

    /* cvoerity 问题修复 CID 155815*/
    if (NULL !=ptr)
    {
        
        printf("%s %s %d  %d:%d:%d UTC %d\n",wday[ptr->tm_wday],mon[ ptr->tm_mon+1],
            ptr->tm_mday,ptr->tm_hour,ptr->tm_min,ptr->tm_sec, ptr->tm_year+1900);
    }
    else
    {
        printf("getDateInfocmd ptr is NULL");
        return EFAIL;
    }
    return SOK;
}
/*******************************************************************************
* 函数名  : helpcmd
* 描  述  : 显示可用命令
* 输  入  : unsued param
* 输  出  : 无
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
static Int32 helpcmd(Int32 argc , Char **argv )
{
	Int32 i,j;
    //int cnt = cmdCnt;  //use when loadcmd from config file
    Int32 cnt = MAX_CMD_CNT ; //use when cmd is inited in program
    int strLen = 0;
	printf("Support Commands:\n\n");

    for (i = 0; i < (cnt/3); i++)
    {        
        strLen = strlen(cmds[i*3]);
        printf("%s",cmds[i*3]);
        for(j = 0;j < (30-strLen);j++)
            printf(" ");
        printf("%s",cmds[i*3+1]);
        strLen = strlen(cmds[i*3+1]);
        for(j = 0;j < (30-strLen);j++)
            printf(" ");
        printf("%s\n",cmds[i*3+2]);     
              
    }
#if 0   // it can be used when cmdcount is alteration
    switch (cnt%3)
    {
        case 0:
            break;
        case 1:
             printf("%s\n",cmds[i*3]);
            break;
        case 2:
#endif
            strLen = strlen(cmds[i*3]);
            printf("%s",cmds[i*3]);

#if 0
            break;
    }
#endif
    printf("\n");
    printf("Please set UTF-8 character encoding format in terminal for displaying Qrcode\n");
    
	return SOK;
}

/*******************************************************************************
* 函数名  : cmd_ask
* 描  述  : 获取输入
* 输  入  : fd     : 文件句柄
            timeout: 超时时间
            prompt : 提示信息
            echoBackFlg : 回显标志，1:回显 0:隐藏
* 输  出  : 无
* 返回值  : 输入字符串
*******************************************************************************/
char* get_cmd(const Int32 fd, Int32 timeout, const String prompt,Int32 echoBackFlg)
{
	/* Was static char[BIGNUM] */
	enum { sizeof_passwd = 1024 };
	static String passwd;
    //int cnt = 0;
    String ret = NULL;
	Int32 i = 0;
	struct sigaction sa, oldsa;
	struct termios tio, oldtio;
    Int32 flags = 0;

    flags = fcntl(fd,F_GETFL);
    flags &= ~O_BLOCK;
    if(fcntl(fd,F_SETFL,flags))
    {
        perror("fcntl(fd,F_SETFL,flags)");
    }

	if(tcgetattr(fd, &oldtio) != 0)
    {
       printf("tcgetattr failed!\n");
    }
	tcflush(fd, TCIFLUSH);
	tio = oldtio;
#ifndef IUCLC
# define IUCLC 0
#endif
	tio.c_iflag &= ~(IUCLC|IXON|IXOFF|IXANY);
	if(echoBackFlg == 1)
	{
		tio.c_lflag &= (ECHO|ECHOE|ECHOK|ECHONL|TOSTOP);
	}
	memset(&sa, 0, sizeof(sa));
	/* coverity 问题消除 CID 152950 */
	if (sigaction(SIGINT, &sa, &oldsa))
	{
		printf("[func:%s line:%d]sigaction error\n",__func__,__LINE__);
	}
    signal(SIGINT,SIG_IGN);	//shield inttrupt(^C) open
	if (timeout) 
    {
		/* coverity 问题消除 CID 152950 */
		if (sigaction(SIGALRM, &sa, NULL))
		{
			printf("[func:%s line:%d]sigaction error\n",__func__,__LINE__);
		}
		alarm(timeout);
	}

	fputs(prompt, stdout);
	fflush(NULL);

	if (!passwd)
		passwd = malloc(sizeof_passwd);
	ret = passwd;
	i = 0;
	while (1) {
		int r = read(fd, &ret[i], 1);
		if (r < 0) {
			/* read is interrupted by timeout or ^C */
            printf("interrupt");
			ret = NULL;
			break;
		}
					
		if (r == 0 /* EOF */
		|| ret[i] == '\r' || ret[i] == '\n' /* EOL */
		|| ++i == sizeof_passwd-1 /* line limit */
		) {
			ret[i] = '\0';/**/
			break;
		}

	}

	if (timeout) {
		alarm(0);
	}
	/*
		covertiy号：152950
		问题描述：修复coverity问题
		修改描述：增加判断
		注意事项描述：无
	*/
	if (sigaction(SIGINT, &oldsa, NULL))
	{
		printf("[func:%s line:%d]sigaction error\n",__func__,__LINE__);
	}
	
	if (tcsetattr(fd, TCSANOW, &oldtio) != 0)
	{
		printf("tcsetattr error\n");
	}
	printf("\n");
	fflush(NULL);
	usleep(10000);
	return ret;
}
/*******************************************************************************
* 函数名  : up_time
* 描  述  : 获取设备运行时间
* 输  入  : 无
* 输  出  : 无
* 返回值  : 运行时间
*******************************************************************************/
Int32 up_time(void)
{
    FILE   *fp       = NULL;
    char   line[30]  = {0};
    Int32  uptime    = 0;
    Int32  i = 0;
    
    if ((fp = fopen(PROC_UPTIME ,"r")) != NULL)
    {
        fgets(line,sizeof(line),fp);
        fseek(fp,0,0);
        fclose(fp);
    } 

    for (i = 0;i < 30;i++)
    {
        if(line[i] == '.')
            break;
		if ((line[i] < 0x30) || (line[i] > 0x39))
			return 0;
    }
	if (i < 30)
		line[i] = 0;
    uptime = atoi(line); 
	
    return uptime;
}
/*******************************************************************************
* 函数名  : getcmdpara
* 描  述  : 分解命令字符串 
* 输  入  : input   :输入字符串
* 输  出  : argcNum :参数个数
* 返回值  : 分解后的参数
*******************************************************************************/
char **getcmdpara(Int32 **argcNum,Char *input)
{
    static  Int32  dargc;
    String  buf =  input;
    String  outer_ptr = NULL;
    String  inner_ptr = NULL;
    const   String split = " ";
    static  String p[3] = {NULL,NULL,NULL};
    
	dargc = 0 ;
	
    while ((p[dargc] = strtok_r(buf,split,&outer_ptr)) != NULL)
    {
        buf = p[dargc];
        while ((p[dargc] = strtok_r(buf,split,&inner_ptr)) != NULL)
        {
            dargc++;
            buf = NULL;
        }
        buf = NULL;
    }
    *argcNum = &dargc;

	return p;
}
/*******************************************************************************
* 函数名  : get_ethaddr
* 描  述  : 获取设备mac地址
* 输  入  : ifname ：网卡名
* 输  出  : addr ：mac地址
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
static int get_ethaddr(char *ifname,unsigned char *addr)
{
#if defined(NF5180) || defined(NF5120)
 	FILE *fp;
    char path[100] = {0}; 

    const char *command = "fw_printenv -n dev_addr";

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to run command");
        return EFAIL;
    }

	fgets(path, sizeof(path), fp);

    pclose(fp);

    sscanf(path, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);
#else
    int    sockfd = 0;
    struct ifreq ifr;
 
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket error!\n");
        return EFAIL;
    }
 
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, (sizeof(ifr.ifr_name) - 1), "%s", ifname);
 
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0 )
    {
        perror("ioctl error!\n");
        close(sockfd);
        return EFAIL;
    }
    close(sockfd);
 
    memcpy((void *)addr, (const void *)&ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
#endif
    return SOK;
}
/*******************************************************************************
* 函数名  : get_rand
* 描  述  : 获取随机数
* 输  入  : r  ：字符串
            len： 字符串长度
* 输  出  : 
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
int get_rand(char *r, int len) 
{
	int randfd =-1;
	int rLen   = 0;
	randfd = open("/dev/random", O_RDONLY|O_NONBLOCK);
	if (-1 == randfd)
	{
		randfd = open("/dev/urandom", O_RDONLY);
		if (-1 == randfd)
		{
			return EFAIL;
		}
	}
	else
	{
		while(1)
		{
			rLen = read(randfd, r, len);
			if (rLen > 0)
			{
				break;
			}
			else
			{
				rLen = read(randfd, r, 1);
				if (rLen > 0)
				{
					break;
				}
			}
			usleep(1000);
		} 
	}
	
	close(randfd);
	
	return SOK;
}
/*******************************************************************************
* 函数名  : get_urrand
* 描  述  : 获取随机数
* 输  入  : r  ：字符串
            len： 字符串长度
* 输  出  : 
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
int get_urrand(char *r, int len) 
{
	int randfd ;

	randfd = open("/dev/urandom", O_RDONLY);
	if (-1 == randfd)
	{
		return EFAIL;
	}

	read(randfd, r, len);
	close(randfd);
	
	return SOK;
}
/*******************************************************************************
* 函数名  : shellcmd
* 描  述  : ashll鉴权
* 输  入  : unused param
* 输  出  : 
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
static Int32 shellcmd(int argc , Char **argv )
{
    String   cp         = NULL;
	Uint8    mac[SVSH_MAC_LEN]   = {0};
	Uchar    serial[SVSH_SN_LEN] = {0};
	Int32    i = 0,ret = 0,len = 0 ,id =0;
    static   Int32 old_id ;
	

    static Int32 getVeriFlg;
    static Int32 runTime,runTime1;
    static Int32 upTime;
    static Int32 tryCountDown;
    static Int32 tryTimes = 0 ;
    static Int32 oldtryTimes = 0 ;
    static time_t svshTime;
	static int   rand;
	char   rand_value[4] = {0};

    static struct termios oldTemo,newTemo;	
    Int32  status   = 0;
    static int once = 0;	
    pid_t  pid      = 0;
    pid_t  inId     = 0;
    Char   *dsh_argv[2] = {NULL,NULL};
    Char   *url = NULL;
    static void   *h;
    Char   urlCmd[MAX_URL_LEN];

    
    if (tryTimes == MAX_TRY_TIMES-1)
    {
        if ((up_time()-tryCountDown) > SECONDS_OF_HALFHOUR)
        {
            tryTimes = 0;
            oldtryTimes = 0;
        }else
        {
           printf("Please try later.\n"); 
           return EFAIL;
        }
        
    }
   
    /*get rand in sn*/
	status = get_urrand((char*)serial, SVSH_SN_LEN);
    /*get mac*/
	status = get_ethaddr(DEFAULT_IFNAME,mac);
    /*get Domain Accounts*/
	cp  = get_cmd(STDIN_FILENO, 0, "Domain Accounts:",1);
	if (NULL == cp)
	{
		return EFAIL;
	}
	len = strlen(cp);
    if ((len > 6) && (*cp > 0x31))
    {
        printf("Domain Accounts  not avaliable\n");
        old_id = id - 1;
        return EFAIL;
    }

    for (i = 0;i < len;i++)
	{
        if ((*cp > 0x39) || (*cp < 0x30))
        {
            printf("Domain Accounts  not avaliable\n");
            old_id = id - 1;
            return EFAIL;
        }
		cp++;
	}
	
	cp -=len;	
	id = atoi(cp);
	
    if ( (id <= 0) || (id >1000000))
    {
        printf("Domain Accounts  not avaliable\n");
        old_id = id - 1;
        return EFAIL;
    }
    
   

    if (getVeriFlg == 0)                          
    {
        svshTime   = time(0);   
        getVeriFlg  = 1;
        runTime = (svshTime /SECONDS_OF_DAY)*SECONDS_OF_DAY+SECONDS_OF_DAY-svshTime ;  //residual effective time of dynamic passwd
        upTime = up_time();                                                            //mark the time of authentication
		status = get_rand(rand_value, 4);
		if (SOK == status)
		{
			rand = (rand_value[0]<<24) | (rand_value[1]<<16) |(rand_value[2]<<8) | rand_value[3];
			h = svsh_open(id, mac,serial,rand);
		}
		else
		{
			return EFAIL;
		}
        printf("Please scan QRcode\n");
    }
    else
    {
        if ((up_time()-upTime) > runTime )                                             //passwd out of effective time
        {
            svsh_close(h);            
            svshTime= time(0);
            runTime = (svshTime/SECONDS_OF_DAY)*SECONDS_OF_DAY+SECONDS_OF_DAY-svshTime;
            upTime = up_time();  
            status = get_rand(rand_value, 4);
			if (SOK == status)
			{
				rand = (rand_value[0]<<24) | (rand_value[1]<<16) |(rand_value[2]<<8) | rand_value[3];
				h = svsh_open(id, mac,serial,rand);
			}
			else
			{
				return EFAIL;
			}
            printf("Please scan QRcode\n");
        }

        if (id != old_id)
        {
            svsh_close(h);
            h = svsh_open(id, mac,serial,rand);
            printf("Please scan QRcode\n");
        }
        else
        {
            if (((up_time()-upTime) < runTime) && (tryTimes == oldtryTimes))
            {
                runTime1 = (time(0)/SECONDS_OF_DAY)*SECONDS_OF_DAY+SECONDS_OF_DAY-time(0);
                printf("Remaining effective time of check code:%d min %d s , you can use last check code\n",runTime1/60,runTime1%60);  
            }
        }
        
    }
    /*get file*/
     old_id = id;
	
	if(h != NULL)
	{
        printf("\n");
        url = svsh_geturl(h);
		if (NULL == url)
		{
			return EFAIL;
		}
        len = strlen(url);
        status = sprintf(urlCmd,"%s%c%s%c",QRCODE, '"',url,'"');

        /*printf("QR message : %s\n",url);*/
		if (status != EFAIL)
		{
			status = system(urlCmd);    
        }
        cp = get_cmd(STDIN_FILENO, 0, "Check codes :",0);
		if (NULL == cp)
		{
			return EFAIL;
		}
        len = strlen(cp);

		if ((len < SVSH_CHECKCODE_LEN +1) &&(svsh_verify(h, cp) != 0) && ((up_time()-upTime) < runTime))
        {
             
            tryTimes = 0;     

            if (once == 0)	
            {       

                tcgetattr(0, &oldTemo);   
                once++;
            }
            memcpy(&newTemo, &oldTemo,sizeof(oldTemo));	
            newTemo.c_lflag &= ~(ICANON );
            if (tcsetattr(0, TCSANOW, &newTemo) != 0)
			{
				printf("tcsetattr error\n");
			}
            
            pid = fork();
            inId= tcgetpgrp(0);
    		if (pid != 0)
            {
                sh_pid = pid;
                alarm(SECONDS_OF_HOUR);
				
				//如果祖先进程中有sonia，证明这个dsh是从sonia中启动的
				if (checkProcAnstor(getpid(), "sonia")||checkProcAnstor(getpid(), "Challenge"))
				{
					while (1)
					{
						ret = waitpid(pid, &status, WNOHANG);
						
						//判断sonia是否还存在，不存在就杀死子进程sh，自己也退出
						//避免出现和第一个sh抢控制台导致不断的#interrupt打印
						if ((!checkProcAnstor(getpid(), "sonia"))&&(!checkProcAnstor(getpid(), "Challenge")))
						{
							kill(sh_pid, SIGHUP);
							exit(0);
						}
						else if ((ret == pid) || (ret == -1))
						{
							break;
						}
						
						usleep(200 * 1000);
					}
				}
				else
				{
					waitpid(pid, &status, 0);
				}

                sh_pid=0;
                while(1)		
                {                
                    tcsetpgrp(0,inId); 
                    
                    usleep(100000);         
                    if ((getpgrp() == tcgetpgrp(0)) || (tcgetpgrp(0)== -1))          
                        {               
							break;        
                        }      
                } 
                if (tcsetattr(0, TCSANOW, &oldTemo) != 0)
				{
					printf("tcsetattr error\n");
				}

    		}else
            {      		
				if(access("/bin/busybox", R_OK) != 0)
				{
						dsh_argv[0] = (char *)"/bin/bash";
						dsh_argv[1] = NULL;
						execve("/bin/bash",dsh_argv,environ);
				}
				else
				{	
						dsh_argv[0] = (char *)"-/bin/sh";
						dsh_argv[1] = NULL;
						execve("/bin/busybox",dsh_argv,environ);
				}
            }
			printf("Hangup\n");
            return 0;
            
        }else
        {
            printf("Verify failed.\n");
            oldtryTimes = tryTimes; 
            tryTimes ++;
            printf("You have %d chances left\n",5-tryTimes); 
            if (tryTimes == MAX_TRY_TIMES -1)
            {
                tryCountDown = up_time();
                printf("Please try again after 30mins.\n"); 
                return EFAIL;
            }
        }

	}
    
	return SOK;
}
/*******************************************************************************
* 函数名  : applet_usable
* 描  述  : 判断是否为可信命令
* 输  入  : applet_name: 输入的命令
* 输  出  : 无
* 返回值  : SOK  : 可信
*           EFAIL: 不可信
*******************************************************************************/
static Int32 applet_usable(char *applet_namee )
{
    
    Int32 i;
	if (applet_namee == NULL)
	{
		return EFAIL;
	}
    //for (i = 0; i < cmdCnt; i++)	//use when loadcmd
    for (i = 0; i < MAX_CMD_CNT; i++)
    {          
        if (!strcmp(applet_namee,cmds[i]))          
        {               
             return SOK;     
        }      
    }
   
   return EFAIL;
}
/*******************************************************************************
* 函数名  : findCmdBuiltin
* 描  述  : 检查命令是否是内置命令，若是则执行命令
* 输  入  : unused param
* 输  出  : 无
* 返回值  : SOK  : 内置命令
*           EFAIL: 外置命令
*******************************************************************************/
Int32 findCmdBuiltin(Int32 dargc,char ** dargv)
{
    Int32 i = 0;

	for (i = 0;i < MAX_BUILTIN_CMD;i++)
	{
		if(builtintab[i].builtin == NULL)
		{
			return EFAIL;
		}
        
		if (!strcmp(dargv[0],builtintab[i].name))          
        {               
            /*execute it if it is builtcmd*/
            builtintab[i].builtin(dargc,dargv);
			return SOK;        
        } 
	}
	return EFAIL;
}
/*******************************************************************************
* 函数名  : findPidByName(String pProgram)
* 描  述  : 检查进程名对应的pid
* 输  入  : pProgra:进程名
* 输  出  : 无
* 返回值  : atoi(pid) : pid值
*           EFAIL: 失败
*******************************************************************************/
Int32 findPidByName(String pProgram)
{
    FILE *fp  = NULL;  
	String lineFp = NULL;
    Char line[100] = {0};
    Char pid[15]={0}, user[15]={0}, time1[15]={0}, program[35]={0},subProgram[35]={0};
    Char *process_sh = "/bin/sh";
    Uint32 i = 0;

    #ifdef ZW_DM365
    Char state[15];
    #endif

	fp = popen("ps","r");
	if (fp != NULL)
	{
		lineFp = fgets(line, sizeof(line), fp);
		if(lineFp == NULL)
		{
			pclose(fp);
            return EFAIL;
		}
		while (fgets(line, sizeof(line), fp))
        {
			if((line[4] > 0x39) || (line[4]) < 0x30)
			{
				continue;
			}
            #ifdef ZW_DM365
            sscanf(line,"%s   %s   %s   %s   %s",pid,user,time1,state,program);
            #else
       		sscanf(line,"%s   %s   %s   %s",pid,user,time1,program);
            #endif
            for(i=0;i<35;i++)
            {
                if(program[i] < 0x21)
                {
                    program[i] = '\0';
                    break;
                }
            }
            program[34]= 0;
            if (strstr(program, pProgram))
            {
				/*
					covertiy号：152131 152130
					问题描述: 关闭资源使用的接口有问题
					修改描述：把fclose改为pclose
					注意事项描述：无
				*/
                pclose(fp);
                return atoi(pid);
            }
            else
            {
                if(strstr(program,process_sh))
                {
                    #ifdef ZW_DM365
                    sscanf(line,"%s   %s   %s   %s   %s   %s",pid,user,time1,state,program,subProgram);
                    #else
           		    sscanf(line,"%s   %s   %s   %s   %s",pid,user,time1,program,subProgram);
                    #endif

                    if (strstr(subProgram, pProgram))
                    {
                        pclose(fp);
                        return atoi(pid);
                    }
                }
                
            }
		}
	}

    if(fp != NULL)
		pclose(fp);
    return EFAIL;
}
/*******************************************************************************
* 函数名  : getPpidFromProc(int pid, char *pName)
* 描  述  : 获取某进程的父进程名及pid
* 输  入  : pi:进程pid值
* 输  出  : pNam:本进程名臣
* 返回值  : atoi(pid) : 父进程pid值
*           EFAIL: 失败
*******************************************************************************/
Int32 getPpidFromProc(int pid, char *pName)
{
	FILE *fp  = NULL;
	Int32 status = 0;
    Int32 i = 0;
	Char str[25] = {0};
	Char procStr[50] ={0};
	static Char  ppid[15] = {0};
	Char id[15] = {0}, name[15] = {0}, stat[15] = {0};
	Char line[100] = {0};
	
	sprintf(str,"%d",pid);
	
	status = sprintf(procStr,"%s%s%s","/proc/", str,"/stat");
	if (status!= EFAIL)
	{
		fp = fopen(procStr,"r");
	}

	if (fp != NULL)
	{
		if (fgets(line, sizeof(line), fp) != NULL)
		{
			sscanf(line,"%s   %s   %s   %s",id,name,stat,ppid);
			for(i=0;i<15;i++)
			{
				if(name[i] < 0x21)
				{
					name[i] = '\0';
					break;
				}
			}
			for(i=0;i<15;i++)
			{ 
				pName[i] = '\0';
			}
			memcpy(pName, name, i);

			fclose(fp);
			return atoi(ppid);
		}
		
		fclose(fp);
	}

	return EFAIL;
}

/*******************************************************************************
* 函数名  : checkProcAnstor(pid_t pid, const char *ancestorName)
* 描  述  : 检查id号为pid的进程的祖先中是否存在名为ancestorName的进程
* 输  入  : pid:进程pid值
* 输  出  : ancestorName:要检查的祖先进程名
* 返回值  : 1 pid的祖先中包含名为ancestorName的进程
*           0 pid的祖先中不包含名为ancestorName的进程
*******************************************************************************/
static Bool checkProcAnstor(pid_t pid, const char *ancestorName)
{
	char parentName[128];
	char matchAncestorName[128];
	Int32 ppid;
	int maxDepth = 30;
	
	snprintf(matchAncestorName, sizeof(matchAncestorName), "(%s)", ancestorName);
	ppid = pid;
	while (maxDepth-- > 0)
	{
		ppid = getPpidFromProc(ppid, parentName);
		if (ppid == EFAIL)
		{
			break;
		}
		
		if (strncmp(matchAncestorName, parentName, sizeof(parentName)) == 0)
		{
			return 1;
		}
	}
	return 0;
}

/*******************************************************************************
* 函数名  : check_exit(char *name)
* 描  述  : 检查命令是否是退出到应用命令，若是则执行命令
* 输  入  : unused param
* 输  出  : 无
* 返回值  : SOK  : 内置命令
*           EFAIL: 外置命令
*******************************************************************************/
int check_exit(char *name)
{	
	int  spid = 0,i = 0, n = 0, sum = 0;
	FILE *fp  = NULL;
	String lineFp = NULL;
	char ppid[15],pid[15], user[15], time1[15],  program[25];
	char line[1000];
    Char aName[15] = {0};
    int ret = 0;
    pid_t soniaPpid = 0,dshPid =0;
    #if defined(ZW_DM365) || defined(APQ8053_32)
    Char state[15];
    #endif
	
	if (strcmp(name,"return"))
	{
		return EFAIL;
	}
	
	spid = getppid();
	n = spid;
    while (n)
    {
        sum++;
        n/=10;
    }

	sprintf(ppid,"%d",spid);

	fp = popen("ps","r");
	if (fp != NULL)
	{		
		lineFp = fgets(line, sizeof(line), fp);
		if(lineFp == NULL)
		{
			goto failed;
		}
		while (fgets(line, sizeof(line), fp))
        {	
			if((line[4] > 0x39) || (line[4]) < 0x30)
			{
				continue;
			}
 #if defined(ZW_DM365)
            sscanf(line,"%s   %s   %s   %s   %s",pid,user,time1,state,program);
 #elif defined(APQ8053_32)
 			sscanf(line,"%s   %s   %s   %s   %s   %s   %s",pid,user,time1,state,state,state,program);
 #else
            ret = sscanf(line, "%s   %s   %s   %s", pid, user, time1, program);
 #endif
            if (ret < 0)
            {
                pclose(fp);
                return EFAIL;
            }
			for (i = 0;i < 15; i++)
			{
				if((pid[i] > 0x39) || (pid[i]) < 0x30)
				{
					pid[i]= '\0';
					break;
				}
			}
			if (!memcmp(pid,ppid,sum))
            {
				for (i = 0;i < 15;i++)
				{
					if((program[i] < 0x60) || (program[i] > 0x7a))
					{
						program[i] = '\0';
						break;
					}
				}
#if defined(NF5180) || defined(NF5120)
				if (!memcmp(program,"sudo",4)){//NF5180中dsh的父进程为sudo /bin/dsh
#else
				if (!memcmp(program,"sh",2)){
#endif
                    dshPid = getppid();
                    while (dshPid != 1)
                    {
                        dshPid = getPpidFromProc(dshPid,aName);
                        if(strstr(aName,"dsh"))
                        {
                            break;
                        }         
                    }
					
                    if ((dshPid != 1) || (NULL != strstr(aName,"dsh")))
                    {
                        if( pgid_flg == -1)
                        {
                            soniaPpid = findPidByName("sonia"); 
							if ((soniaPpid < 0) || (soniaPpid > 0x7ffff))
							{
								soniaPpid = findPidByName("Challenge");
								if ((soniaPpid < 0) || (soniaPpid > 0x7ffff))
								{
									goto failed;			
								}
							}
						
                            soniaPpid = getPpidFromProc(soniaPpid,aName);
							if ((soniaPpid < 0) || (soniaPpid > 0x7ffff))
							{
								goto failed;
							}

                            tcsetpgrp(0,soniaPpid);
                        }
                        else
                        {								
                            tcsetpgrp(0,old_forcePid);
                        }
                    }else
                    {
                        tcsetpgrp(0,old_forcePid);
                   }

                   kill(spid,SIGHUP);
				   pclose(fp);
                   return SOK;
                }
            }         
		}
	}
failed:
	if(fp != NULL)
		pclose(fp);
    return EFAIL;
}

/*******************************************************************************
* 函数名  : load_cmds
* 描  述  : 载入可信命令列表
* 输  入  : 无
* 输  出  : 无
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
Int32 load_cmds(void)
{	
    Int32 status = 0;	
    Int32 i = 0;	
    Char tmpCmd[MAX_BUF_LEN]= {0};
    Char tmpFormat[20] = {0}; 
    FILE *pFp = fopen(FILE_NAME,"r");	

    if (pFp == NULL)	
    {       
        printf("fileName = %s,open err\n",FILE_NAME);           
        return EFAIL;
    }   
       
    sprintf(tmpFormat,"%%%ds",MAX_BUF_LEN-1);  
    while (i < MAX_CMD_CNT)    
    {       
        status = fscanf(pFp,tmpFormat,tmpCmd);      
        if (status <= 0)    
        {          
            break;     
        }      
      
        cmds[i] = malloc(strlen(tmpCmd)+1);    
        strncpy(cmds[i],tmpCmd,strlen(tmpCmd));    
        i++;    
     }   
    fclose(pFp);   
    cmdCnt = i; 
    
    return SOK;
}
/*******************************************************************************
* 函数名  : checkAppByhand
* 描  述  : 查看应用程序是否是手动启动的
* 输  入  : 无
* 输  出  : 无
* 返回值  : SOK  : 检测是手动启动的
*           EFAIL: 检测失非手动启动
*******************************************************************************/
Int32 checkAppByhand()
{
    Char *proces_sonia = "sonia";
	Char *proces_Challenge = "Challenge";
    Char aName[15] = {0};
    Int32 pid = 0;

     //当sonia进程存在，sonia的父进程中有dsh，并且dsh父进程是appauto，不杀sh，不返回dsh。
    if ((pid = findPidByName(proces_sonia)) < 0)
	{
		if((pid =findPidByName(proces_Challenge)) < 0)
		{
			return EFAIL;
		}
	}
	if (pid > 0)
    {
		while (pid != 1)
        {
            pid = getPpidFromProc(pid,aName);

            if((getpid() == pid) || (NULL != strstr(aName, "busybox")))
            {
                return SOK;
            }
                
        }
#if 0
        if ( getpid() == pid)
        {			
			return SOK;                    
        }
#endif
    }
    return EFAIL;
}

/*******************************************************************************
* 函数名  : signal_alarm
* 描  述  : 定时关闭ashell
* 输  入  : 无
* 输  出  : 无
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
void signal_alarm(void)
{   
    Int32 ret = 0;
    ret = checkAppByhand();

    if(ret != SOK)
    {
        if (sh_pid != 0) 
        {            
            kill(sh_pid,SIGHUP);   
        }
        
    }
    
}

extern __pid_t tcgetsid (int __fd);
/*******************************************************************************
* 函数名  : init_dsh
* 描  述  : 初始化，屏蔽信号，防止dsh意外退出
* 输  入  : 无
* 输  出  : 无
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
Int32 init_dsh()
{
	//Int32 ret = 0;
	Int32 i;

	old_forcePid = tcgetsid(0);
   if(getpid() == tcgetpgrp(0))
    {
       pgid_flg  = -1;
    }else
    {
        if (setsid() < 0)
        {
            perror("warning: setsid failed.\n");
        }
    }
	for (i = 2;i < 64;i++)
	{
		signal(i,SIG_IGN);	
	}
	signal(SIGALRM,(void *)signal_alarm);
	signal(SIGUSR1,SIG_DFL);
	signal(SIGUSR2,SIG_DFL);
    //signal(SIGHUP,(void *)signal_hup);
	printf("Date&Time: %s %s\n",__DATE__,__TIME__);
	printf("Revision: %s\n",REV);
    printf("Enter 'help' for a list of commands (dsh) \n\n");

	if (NULL == getenv("LD_LIBRARY_PATH"))
	{
		//printf("add LD_LIBRARY_PATH \n");
	    if (0 != setenv("LD_LIBRARY_PATH", "/usr/lib:/lib", 1))
        {
            return EFAIL;
        }   
	}

	/*ret = load_cmds();
	if (ret != 0)
	{
		printf("init error");
		return -1 ;
	}*/
	return SOK;
}

/*******************************************************************************
* 函数名  : main
* 描  述  : 主函数，命令解析与ashell鉴权
* 输  入  : unused param
* 输  出  : 无
* 返回值  : SOK  : 成功
*           EFAIL: 失败
*******************************************************************************/
Int32 main(Int32 argc,Char *argv[])
{
	
    Char      **dargv = NULL;
    Int32     dargc    = 0;
	Int32     ret      = 0;
	Int32     i        = 0;
    Int32     length   = 0;
    Int32     *pArgc  = NULL;
    String    cp = NULL;
    String    pInputcmd = NULL;

	ret = init_dsh();
    if (ret == EFAIL)
    {
        printf("Init error");
        return EFAIL;
    }
    
    pInputcmd = malloc(MAX_CMD_LEN );
    if (pInputcmd == NULL)
    {
        return EFAIL;
    }
    
	while(1)
	{
 
        /*waitting for cmd*/
        cp = get_cmd(STDIN_FILENO, 0, "#",1);       
		if (NULL == cp)
		{
            continue;
		}
        length = strlen(cp);
        if (length >= MAX_CMD_LEN )
        {
            continue;
        }else
        {
            memset(pInputcmd,'\0',MAX_CMD_LEN);
        }

        /*analysis command*/
		dargv = getcmdpara(&pArgc,cp);
        dargc = *pArgc;
        if (dargc == 0)
        {
            continue;
        }
        /*judgement "return" comamand */
		ret = check_exit(dargv[0]);	
		if (ret == SOK)
		{
			goto end;
		}
        /*judgement comamand credibility*/
        ret = applet_usable(dargv[0]);
        if (ret == EFAIL)
		{
			printf("%s:Not support try help!\n",dargv[0]);
			continue;
		}

        /*locate commad and excute if it is builtincmd*/
        ret = findCmdBuiltin(dargc,dargv);
		if (ret == SOK)
		{
			continue;
		}else
        {      
        /*execute in ashell if not built*/
			for (i = 0; i < dargc; i++)
			{
				strcat(pInputcmd,dargv[i]);
				strcat(pInputcmd," ");
			}
			ret = system(pInputcmd);
			if (ret == EFAIL )
			{
				printf("system error\n");
			}

        }
       
	}
end:

	if(pInputcmd)
        free(pInputcmd);
	return SOK ;
}
