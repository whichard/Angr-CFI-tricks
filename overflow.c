#include<stdio.h>
#include<string.h>
#define PASSWORD "1234567"
int verify_password(char* password)
{
    int authenticated;
    char buffer[8];//定义一个大小为8字节的数组，控制没溢出的字符串长度，（超出这个长度就会溢出）
    authenticated = strcmp(password,PASSWORD);
    strcpy(buffer,password);//这句话直接导致溢出的发生
    return authenticated;
} 
int main()
{
    int valid_flag = 0;
    char password[1024];
    while(1)
    {
            printf("请输入密码：");
            scanf("%s",password);
            valid_flag = verify_password(password);

            if(valid_flag)
            {
                          printf("密码错误。请重试\n\n\n");
            }        
            else
            {
                          printf("验证通过:)");
                          break;
            }

    }
    
    return 0;
}
