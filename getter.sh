#!/bin/bash

tot=0
fail_cnt=0
suc_cnt=0
info_cnt=0

function AA01(){

  local title1=$1
  local title2=$2
  local title3=$3
  local check=$4
  local resource=$5
  local text=$6

  title1="Cloud Identity Cloud IAM"
  title2="GCP-SEC-AA01"
  title3="패스워드 복잡성 설정"

  command1=`cat /etc/login.defs | grep PASS_MIN_DAYS | awk '{print $2}' | sed '1d'`
  command2=`cat /etc/login.defs | grep PASS_WARN_AGE | awk '{print $2}' | sed '1d'`

  echo "    ==> 최소 사용 시간          :   `cat /etc/login.defs | grep PASS_MIN_DAYS | awk '{print $2}' | sed '1d'`일"
  echo "    ==> 기간 만료 경고 기간(일) :   `cat /etc/login.defs | grep PASS_WARN_AGE | awk '{print $2}' | sed '1d'`일"

  if [[ -n $command1&&$command2 ]]; then
       check="[양호]"
       resource="/etc/login.defs"
       add_suc_tot
       export title1 title2 title3 check resource text tot suc_cnt filename
       sh print.sh

  else check="[취약]"
       resource="/etc/login.defs"
       text="설정 없음"
       add_fail_tot
       export title1 title2 title3 check resource text tot fail_cnt filename
       sh err_chk.sh
       sh print.sh
  fi


}

function AA02(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Identity Cloud IAM"
title2="GCP-SEC-AA02"
title2="패스워드 최소길이 설정"

command=`cat /etc/login.defs | grep PASS_MIN_LEN | awk '{print $2}' | sed '1d'`
echo "    ==> 최소 길이               :   `cat /etc/login.defs | grep PASS_MIN_LEN | awk '{print $2}' | sed '1d'`글자"

if [[ -n $command ]]; then
     check="[양호]"
     resource="/etc/login.defs"
     text=""
     add_suc_tot
     export title1 title2 title3 check resource text tot suc_cnt filename
     sh print.sh

else check="[취약]"
     resource="/etc/login.defs"
     text="최소길이 설정 없음"
     add_fail_tot
     export title1 title2 title3 check resource text tot fail_cnt filename
     sh err_chk.sh
     sh print.sh
fi
}

function AA03(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Identity Cloud IAM"
title1="GCP-SEC-AA03"
title2="사용자 패스워드 변경 허용"


PP=`ls -l /etc/passwd | awk {'print $1'}`
PO=`ls -l /etc/passwd | awk {'print $3'}`
PG=`ls -l /etc/passwd | awk {'print $4'}`

if [ $PP = -r--r--r--. ]
	then
    echo "    ==> [안전] 권한   : " $PP
    check="[양호]"
    text="-"
    resource="/etc/passwd"
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh
else
	if [ $PP = -rw-r--r--. ]
		then
			echo "    ==> [안전] 권한   : " $PP
            check="[양호]"
            text="-"
            resource="/etc/passwd"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh
		else
			echo "    ==> [취약] 권한   : " $PP
            check="[취약]"
            text="권한 설정에 취약점 발견"
            resource="/etc/passwd"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi
    fi

if [ $PO = root ]
	then
		echo "    ==> [안전] 소유자 : " $PO
        check="[양호]"
        text="소유자 권한 양호"
        resource="/etc/passwd"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
	else
		echo "    ==> [취약] 소유자 : " $PO
        check="[취약]"
        text="소유자 권한 취약"
        resource="/etc/passwd"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi

if [ $PG = root ]
	then
		echo "    ==> [안전] 그룹   : " $PO
        check="[양호]"
        text="-"
        resource="/etc/passwd"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
	else
		echo "    ==> [취약] 그룹   : " $PO
        check="[취약]"
        text="소유자 권한 취약"
        resource="/etc/passwd"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi

}

function AA04(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Identity Cloud IAM"
title2="GCP-SEC-AA04"
title3="패스워드 최대 사용기간 설정"

command=`cat /etc/login.defs | grep PASS_MAX_DAYS | awk '{print $2}' | sed '1d'`
echo "    ==> 최대 사용기간             :   `cat /etc/login.defs | grep PASS_MAX_DAYS | awk '{print $2}' | sed '1d'`일"

if [[ -n $command ]]; then
     check="[양호]"
     text="-"
     resource="/etc/login.defs"
     add_suc_tot
     export title1 title2 title3 check resource text tot suc_cnt filename
     echo "최대 사용 기간          :   `cat /etc/login.defs | grep PASS_MAX_DAYS | awk '{print $2}' | sed '1d'`일"
     sh print.sh

else check="[취약]"
     text="패스워드 최대 사용기간 설정 없음"
     resource="/etc/login.defs"
     add_fail_tot
     export title1 title2 title3 check resource text tot fail_cnt filename
     sh err_chk.sh
     sh print.sh
fi

}

function AA05(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Identity Cloud IAM"
title2="GCP-SEC-AA05"
title3="불필요한 계정 제거"

AA05=$(gcloud auth list --format="json" | jq '.[].status')

  if [ $AA05 = ACTIVE ]; then
        check="[양호]"
        resource=$AA05
        text="-"
        #resource="/etc/login.defs"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
        
    elif [[ -z $AA05 ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}

function AA06(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Identity Cloud IAM"
title2="GCP-SEC-AA06"
title3="권한 그룹 관리"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
export title1 title2 title3 check resource text tot filename
add_info_tot
sh err_chk.sh
sh print.sh
}

function AA07(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Identity Cloud IAM"
title2="GCP-SEC-AA07"
title3="불필요한 Role 제거"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
export title1 title2 title3 check resource text tot filename
add_info_tot
sh err_chk.sh
sh print.sh
}


function AB01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Identity-Aware Proxy(IAP)"
title2="GCP-SEC-AB01"
title3="사용자 액세스 관리"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
export title1 title2 title3 check resource text tot filename
add_info_tot
sh err_chk.sh
sh print.sh
}


# function AB02(){

# local title1=$1
# local title2=$2
# local title3=$3
# local check=$4
# local resource=$5
# local text=$6
 

# title1="Identity-Aware Proxy (IAP)"
# title2="GCP-SEC-AB02"
# title3="TCP 전달을 위한 Cloud IAP 사용"


# com= jq -rc '.[].asset.resourceProperties.allowed |select(.) |fromjson |.[] |.ports |select(.)' ${filename} |
# while read -r com; do
#     TFCHK="$(echo "$com" | jq .state)"
#     resource="$(echo "$com" | jq .name)"

#     if [[ $TFCHK =~ ENABLED ]]; then
#           check="[양호]"
#           text=""
#           resource=$resource
#           add_suc_tot
#           export title1 title2 title3 check resource text tot suc_cnt
#           sh print.sh

#     elif [[ $TFCHK =~ DESTROYED ]]; then
#           check="[취약]"
#           text="IAP 설정 없음"
#           resource=$resource
#           add_fail_tot
#           export title1 title2 title3 check resource text tot fail_cnt
#           sh err_chk.sh
#           sh print.sh

#     elif [[ -z $TFCHK ]]; then
#           check="[정보]"
#           resource="-"
#           text="Cloud IAP 리소스 없음"
#           add_fail_tot
#           export title1 title2 title3 check resource text tot fail_cnt
#           sh err_chk.sh
#           sh print.sh
#     fi
# done
# }

function AB03(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Identity-Aware Proxy(IAP)"
title2="GCP-SEC-AB03"
title3="컨텍스트 인식 액세스 설정"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
export title1 title2 title3 check resource text tot filename
add_info_tot
sh err_chk.sh
sh print.sh
}


function AB06(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Identity-Aware Proxy(IAP)"
title2="GCP-SEC-AB06"
title3="외부 ID 사용설정"

check="[정보]"
text="콘솔에서 확인 필요"
export title1 title2 title3 check resource text tot filename
add_info_tot
sh err_chk.sh
sh print.sh
}

function AC01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Identity-Aware Proxy(IAP)"
title2="GCP-SEC-AC01"
title3="강화된 인증방식 적용"

check="[정보]"
text="콘솔에서 확인 필요"
export title1 title2 title3 check resource text tot filename
add_info_tot
sh err_chk.sh
sh print.sh
}

function AD01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

command=$(jq '.[].asset.resourceProperties.primary |select(.) |fromjson |.state' ${filename})
title1="Cloud Key Management Service"
title2="GCP-SEC-AD01"
title3="키 버전 설정 및 중지"


com= jq -rc '.[].asset.resourceProperties.primary|select(.)|fromjson' ${filename} |
while read -r com; do
    TFCHK="$(echo "$com" | jq .state)"
    resource="$(echo "$com" | jq .name)"

    if [[ $TFCHK =~ ENABLED ]]; then
          check="[양호]"
          text="-"
          resource=$resource
          add_suc_tot
          export title1 title2 title3 check resource text tot suc_cnt filename
          sh print.sh

    elif [[ $TFCHK =~ DESTROYED ]]; then
          check="[취약]"
          text="IAP 설정 없음"
          resource=$resource
          add_fail_tot
          export title1 title2 title3 check resource text tot fail_cnt filename
          sh err_chk.sh
          sh print.sh

    elif [[ -z $TFCHK ]]; then
          check="[정보]"
          resource="Cloud IAP 리소스 없음"
          text="-"
          add_fail_tot
          export title1 title2 title3 check resource text tot fail_cnt filename
          sh err_chk.sh
          sh print.sh
    fi
done
}


# function AD02(){

# local title1=$1
# local title2=$2
# local title3=$3
# local check=$4
# local resource=$5
# local text=$6

# command=$(jq '.[].asset.resourceProperties.primary |select(.) |fromjson |.state' ${filename})

# title1="Cloud Key Management Service"
# title2="GCP-SEC-AD02"
# title3="키 버전 폐기"

#   for RETURNS in $command
#   do
#     read TFCHK <<<"${RETURNS}"
#     echo -e "TFCHK:    ${TFCHK}"

#     if [[ -n $TFCHK  ]]; then
#         if [[ $TFCHK =~ ENABLED ]]; then
#             check="[양호]"
#             resource=$command
#             text="-"
#             echo "리소스: - "
#             add_suc_tot
#             export title1 title2 title3 check resource text tot suc_cnt
#             sh print.sh
#             echo

#         elif [[ ! $TFCHK =~ ENABLED ]]; then
#             check="[취약]"
#             resource="-"
#             text="리소스 없음"
#             add_fail_tot
#             export title1 title2 title3 check resource text tot fail_cnt
#             sh err_chk.sh
#             sh print.sh
#         fi

#     elif [[ -z $TFCHK ]]; then
#         check="[취약]"
#         resource="-"
#         text="리소스 없음"
#         add_fail_tot
#         export title1 title2 title3 check resource text tot fail_cnt
#         sh err_chk.sh
#         sh print.sh
#     fi
# done
# }


function AD04(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6
 

title1="Cloud Key Management Service"
title2="GCP-SEC-AD04"
title3="Cloud HSM 클러스터 관리"


com= jq -rc '.[].asset.resourceProperties|select(.protectionLevel=="HSM")' ${filename} |
while read -r com; do
    HSMCHK="$(echo "$com" | jq '.name')"
    RSCCHK="$(jq '.[].asset.securityCenterProperties| select(.resourceType=="google.cloud.kms.CryptoKey")')"

    if [[ $HSMCHK ]]; then
          check="[양호]"
          text=""
          resource=$HSMCHK
          add_suc_tot
          export title1 title2 title3 check resource text tot suc_cnt filename
          sh print.sh


    elif [[ -z $HSMCHK ]]; then
          check="[취약]"
          resource="-"
          text="HSM 클러스터 없음"
          add_fail_tot
          export title1 title2 title3 check resource text tot fail_cnt filename
          sh err_chk.sh
          sh print.sh
    fi
done


    if [[ -z  $RSCCHK ]]; then
          check="[정보]"
          resource="암호화 키 리소스 없음"
          text="-"
          add_info_tot
          export title1 title2 title3 check resource text tot info_cnt filename
          sh err_chk.sh
          sh print.sh
    fi
}


function AD05(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6
 

title1="Cloud Key Management Service"
title2="GCP-SEC-AD05"
title3="Cloud EKM 키 관리"

RSCCHK="$(jq '.[].asset.securityCenterProperties| select(.resourceType=="google.cloud.kms.KeyRing")' ${filename})"

com= jq -rc '.[].asset.resourceProperties|select(.protectionLevel=="EKM")' ${filename} |
while read -r com; do
    EKMCHK="$(echo "$com" | jq '.name')"
    
    if [[ $EKMCHK ]]; then
          check="[양호]"
          text=""
          resource=$EKMCHK
          add_suc_tot
          export title1 title2 title3 check resource text tot suc_cnt filename
          sh print.sh
    fi
done

    if [[ -z $RSCCHK ]]; then
          check="[정보]"
          resource="암호화 키 리소스 없음"
          text="-"
          add_info_tot
          export title1 title2 title3 check resource text tot info_cnt filename
          sh err_chk.sh
          sh print.sh

    elif [[ -z $EKMCHK ]]; then
        check="[취약]"
        resource="EKM 클러스터 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}



function AE01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="VPC Firewall Rules"
title2="GCP-SEC-AE01"
title3="네트워크 대역 분리"

command=$(gcloud compute networks subnets list --format=json | jq '.[].selfLink')
for list in $command;
do
    readarray resultArray<<< "$list"
    resource="${resultArray[0]}"

    if [[ -n $command ]]; then
        check="[양호]"
        text=""
        resource=$resource
        add_suc_tot
        export title1 title2 title3 check resource text tot filename
        sh print.sh
        echo


    elif [[ -z $command2 ]]; then
        check="[취약]"
        text="-"
        resource="리소스 없음"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi
done
}


function AE02(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6
 
command=$(jq '.[].asset.resourceProperties|select(.) |.sourceRanges |select(.)|fromjson |.[]' ${filename})
title1="VPC Firewall Rules"
title2="GCP-SEC-AE02"
title3="방화벽 규칙 특정IP 제한"

for returns in $command
do

    if [[ -n $returns  ]]; then
            check="[양호]"
            resource=$returns
            text="-"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh
            fi
    done

        if [[ -z $command ]]; then
            check="[정보]"
            resource="방화벽 규칙 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
    fi
}

function AE03(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6
title1="VPC Firewall Rules"
title2="GCP-SEC-AE03"
title3="패킷 미러링"

command=$(gcloud compute packet-mirrorings list --format="value(NAME)")

for returns in $command
do

    if [[ -n $returns ]]; then
            check="[양호]"
            text=""
            resource=$returns
            add_suc_tot
            export title1 title2 title3 check resource text tot filename
            sh print.sh

        elif [[ -z $command ]]; then
            check="[정보]"
            resource="-"
            text="방화벽 규칙 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
    fi
done
}


function AE04(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="VPC Firewall Rules"
title2="GCP-SEC-AE04"
title3="IP 보안정책 접근 제어"

command=$(jq '.[].asset.resourceProperties|select(.) |.sourceRanges |select(.)|fromjson|.[]' ${filename})

  for ips in $command
  do
        if [[ -n $ips ]]; then
          check="[양호]"
          resource=$ips
          text=""
          add_suc_tot
          export title1 title2 title3 check resource text tot suc_cnt filename
          sh print.sh
  

        elif [[ -z $ips ]]; then
            check="[취약]"
            resource="리소스 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi
done
}


function AE05(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6


title1="VPC Firewall Rules"
title2="GCP-SEC-AE05"
title3="클라우드 보안 정책 모니터링"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
add_info_tot
export title1 title2 title3 check resource text tot info_cnt filename
sh print.sh

}


function AE06(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="VPC Firewall Rules"
title2="GCP-SEC-AE06"
title3="인터넷 연결 차단"

com=$(gcloud compute networks subnets list --format="value(NAME)" | sort -n | uniq )
for i in $com;
do
    if [[ -n $i ]]; then
            check="[양호]"
            text="-"
            resource=$i
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh

        elif [[ -z $i ]]; then
            check="[취약]"
            resource="리소스 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
    fi
done
}


function AE07(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="VPC Firewall Rules"
title2="GCP-SEC-AE07"
title3="최소한의 리소스 연결"

com=$(gcloud compute firewall-rules list --format="value(NAME)" --filter="DISABLED:true")
com2=$(gcloud compute firewall-rules list --format="value(NAME)")
for i in $com;
do
    if [[ -n $i ]]; then
        check="[취약]"
        text="방화벽에 DISABLED 된 방화벽이 포함되어 있음"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi
done
    if [[ -z $i ]]; then
        check="[양호]"
        resource="방화벽 리소스 사용 중 DISABLED 된 방화벽 없음"
        text="-"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh

    elif [[ -z $com2 ]]; then
        check="[정보]"
        resource="방화벽 리소스 없음"
        text="-"
        add_info_tot
        export title1 title2 title3 check resource text tot info_cnt filename
        sh print.sh
    fi
}


function AF01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6


title1="Cloud Armor"
title2="GCP-SEC-AF01"
title3="DOS 공격에 대한 방어 모니터링"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
add_info_tot
export title1 title2 title3 check resource text tot info_cnt filename
sh print.sh

}


function AF02(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6


title1="Cloud Armor"
title2="GCP-SEC-AF02"
title3="웹 어플리케이션 공격 대응 설정"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
add_info_tot
export title1 title2 title3 check resource text tot info_cnt filename
sh print.sh

}


#
# function AE07(){
#
# local title1=$1
# local title2=$2
# local check=$3
# local resource=$4
# local text=$5
#
# title1="GCP-SVC-AF01"
# title2="최소한의 리소스 연결"
# command=$(gcloud beta compute security-policies list --format="value(NAME)")
#
#
# for armor in $command
# do
#   echo -e "armor:    ${armor}"
# done
#
# if [[ -n $command ]]; then
#         check="[양호]"
#         resource="방화벽 설정 있음"
#         echo $title1,$title2,$resource
#         echo -n -e "\033[34m[양호]\033[0m"
#         tot=$(( $(( ${tot}+1 )) ))
#         suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
#         echo
#
# elif [[ -z $command ]]; then
#         check="[취약]"
#         resource="-"
#         text="리소스 없음"
#         tot=$(( $(( ${tot}+1 )) ))
#         fail_cnt=$(( ${fail_cnt}+1 ))
#         export title1
#         export title2
#         export check
#         export resource
#         export text
#         export tot
#         export fail_cnt
#         echo -n -e "\033[33m[취약]\033[0m"
#         sh err_chk.sh
# fi
# }

function AG01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Data Loss Prevention API"
title2="GCP-SEC-AG01"
title3="DLP 서비스 경계 설정"

com=$(gcloud access-context-manager perimeters list)

if [[ $com -gt 0 ]]; then
        check="[양호]"
        text="-"
        resource=$com
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
        echo

    elif [[ -z $com ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}


function AH01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Network Intelligence Center"
title2="GCP-SEC-AH01"
title3="네트워크 토폴로지"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
add_info_tot
export title1 title2 title3 check resource text tot info_cnt filename
sh print.sh
}


function AI01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Network Telemetry"
title2="GCP-SEC-AI01"
title3="VPC 흐름 로그 설정"

command=$(gcloud compute networks subnets list --format="value(name)" --filter="enableFlowLogs:true")

if [[ -n $command ]]; then
        check="[양호]"
        text="-"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh

    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}

function AJ02(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Event Threat Detection"
title2="GCP-SEC-AJ02"
title3="Security Command Center API 설정"

command=$(gcloud services list --enabled --format=json | grep -P "securitycenter.googleapis.com")

if [[ -n $command ]]; then
        check="[양호]"
        text="-"
        resource="securitycenter.googleapis.com"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
  

    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}


function AK01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Security Command Center"
title2="GCP-SEC-AK01"
title3="보안 명령 센터 설정"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
add_info_tot
export title1 title2 title3 check resource text tot info_cnt filename
sh print.sh
}

function AK02(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Security Command Center"
title2="GCP-SEC-AK01"
title3="보안 상태 분석 활성화"

ORG=$(gcloud organizations list --format="value(ID)")
command=$(gcloud scc sources describe organizations/$ORG --source-display-name='Security Health Analytics' | grep 'name')

if [[ -n $command ]]; then
        check="[양호]"
        text="-"
        resource=$command
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh

    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}

function AK04(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Security Command Center"
title2="GCP-SEC-AK04"
title3="감사 정책에 따른 위반사항 수정"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
add_info_tot
export title1 title2 title3 check resource text tot info_cnt filename
sh print.sh
}

function AL01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Security Command Center"
title2="GCP-SEC-AL01"
title3="쿼리언어 모니터링 설정"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
add_info_tot
export title1 title2 title3 check resource text tot info_cnt filename
sh print.sh
}

function AM02(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

AM02="gcloud logging logs list"

title1="Cloud Logging"
title2="GCP-SEC-AM02"
title3="VPC 흐름 로그 설정"

if [[ -n $($AM02 --format=json | grep -P "/logs/cloudaudit.googleapis.com%2Factivity") ]]; then
    check="[양호]"
    text="-"
    echo -n -e "\033[34m 2Factivity : [양호]\033[0m\n"
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh

else echo -n -e "\033[31m 2Factivity : [리소스 없음]\033[0m\n"
    check="[취약]"
    resource="2Factivity : [리소스 없음]"
    text="-"
    add_fail_tot
    export title1 title2 title3 check resource text tot fail_cnt filename
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
    sh print.sh
fi

if [[ -n $($AM02 --format=json | grep -P "/logs/cloudaudit.googleapis.com%2Fdata_access") ]]; then
   echo -n -e "\033[34m 2Fdata_access : [양호]\033[0m\n"
   add_suc_tot
   export title1 title2 title3 check resource text tot suc_cnt filename
  
   sh print.sh
else echo -n -e "\033[31m 2Fdata_access : [리소스 없음]\033[0m\n"
  check="[취약]"
  resource="2Fdata_access : [리소스 없음]"
  text="-"
  add_fail_tot
  export title1 title2 title3 check resource text tot fail_cnt filename
  sh err_chk.sh
  sh print.sh
fi

if [[ -n $($AM02 --format=json | grep -P "/logs/cloudaudit.googleapis.com%2Fsystem_event") ]]; then
   echo -n -e "\033[34m 2Fsystem_event : [양호]\033[0m\n"
   add_suc_tot
   export title1 title2 title3 check resource text tot suc_cnt filename
   sh print.sh

else echo -n -e "\033[31m 2Fsystem_event : [리소스 없음]\033[0m"
  check="[취약]"
  resource="2Fsystem_event : [리소스 없음]"
  text="-"
  add_fail_tot
  export title1 title2 title3 check resource text tot fail_cnt filename
  sh err_chk.sh
  sh print.sh
fi
echo
}

function AP01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Security Scanner"
title2="GCP-SVC-AP01"
title3="웹 보안 스캐너"
command=$(gcloud alpha web-security-scanner scan-configs list --format=json |  grep -e 'targetPlatforms' -e 'startingURLs')
scanner=$(gcloud alpha web-security-scanner scan-configs list --format="value(NAME)")

if [[ -n $command ]]; then
        check="[양호]"
        resource=$(gcloud alpha web-security-scanner scan-configs list --format="value(displayName)")
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
        echo

    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        export title1 title2 title3 check resource text tot fail_cnt filename
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
        sh print.sh
    fi
}

function AQ01(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="공통"
title2="GCP-SVC-AQ01"
title3="사용자 액세스 제어(IAM)"

check="[정보]"
resource="-"
text="콘솔에서 확인 필요"
add_info_tot
export title1 title2 title3 check resource text tot info_cnt filename
sh print.sh
}


function AQ02(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="공통"
title2="GCP-SVC-AQ02"
title3="그룹사용자 및 서비스계정 관리"


    if [[ $command ]]; then
        check="[정보]"
        resource="리소스 없음"
        text="-"
        export title1 title2 title3 check resource text tot info_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}

function AQ03(){


   declare -A apis=(
  ["abusiveexperiencereport.googleapis.com"]="Abusive Experience Report API"
  ["acceleratedmobilepageurl.googleapis.com"]="Accelerated Mobile Pages (AMP) URL API"
  ["accessapproval.googleapis.com"]="Access Approval API"
  ["accesscontextmanager.googleapis.com"]="Access Context Manager API"
  ["actions.googleapis.com"]="Actions API"
  ["adexchangebuyer-json.googleapis.com"]="Ad Exchange Buyer API"
  ["adexchangebuyer.googleapis.com"]="Ad Exchange Buyer API II"
  ["adexchangeseller.googleapis.com"]="Ad Exchange Seller API"
  ["adexperiencereport.googleapis.com"]="Ad Experience Report API"
  ["admin.googleapis.com"]="Admin SDK"
  ["admob.googleapis.com"]="AdMob API"
  ["adsense.googleapis.com"]="AdSense Management API"
  ["adsensehost.googleapis.com"]="AdSense Host API"
  ["alertcenter.googleapis.com"]="G Suite Alert Center API"
  ["analytics.googleapis.com"]="Google Analytics API"
  ["analyticsadmin.googleapis.com"]="Google Analytics Admin API"
  ["analyticsdata.googleapis.com"]="Google Analytics Data API"
  ["analyticsreporting.googleapis.com"]="Analytics Reporting API"
  ["androidcheck.googleapis.com"]="Android Device Verification"
  ["androiddeviceprovisioning.googleapis.com"]="Android Device Provisioning Partner API"
  ["androidenterprise.googleapis.com"]="Google Play EMM API"
  ["androidmanagement.googleapis.com"]="Android Management API"
  ["androidovertheair.googleapis.com"]="Android Over the Air API"
  ["androidpublisher.googleapis.com"]="Google Play Android Developer API"
  ["anthos.googleapis.com"]="Anthos API"
  ["anthosaudit.googleapis.com"]="Anthos Audit API"
  ["anthosconfigmanagement.googleapis.com"]="Anthos Config Management API"
  ["anthosgke.googleapis.com"]="Anthos GKE API"
  ["apigateway.googleapis.com"]="API Gateway API"
  ["apigee.googleapis.com"]="Apigee API"
  ["apigeeconnect.googleapis.com"]="Apigee Connect API"
  ["appengine.googleapis.com"]="App Engine Admin API"
  ["appengineflex.googleapis.com"]="Google App Engine Flexible Environment"
  ["appsmarket-component.googleapis.com"]="Google Workspace Marketplace SDK"
  ["appsmarket.googleapis.com"]="G Suite Marketplace API"
  ["arcorecloudanchor.googleapis.com"]="ARCore Cloud Anchor API"
  ["area120tables.googleapis.com"]="Area120 Tables API"
  ["artifactregistry.googleapis.com"]="Artifact Registry API"
  ["assuredworkloads.googleapis.com"]="Assured Workloads API"
  ["audit.googleapis.com"]="Audit API"
  ["automl.googleapis.com"]="Cloud AutoML API"
  ["bigquery.googleapis.com"]="BigQuery API"
  ["bigqueryconnection.googleapis.com"]="BigQuery Connection API"
  ["bigquerydatatransfer.googleapis.com"]="BigQuery Data Transfer API"
  ["bigqueryreservation.googleapis.com"]="BigQuery Reservation API"
  ["bigquerystorage.googleapis.com"]="BigQuery Storage API"
  ["bigtable.googleapis.com"]="Cloud Bigtable API"
  ["bigtableadmin.googleapis.com"]="Cloud Bigtable Admin API"
  ["bigtabletableadmin.googleapis.com"]="Cloud Bigtable Table Admin API"
  ["billingbudgets.googleapis.com"]="Cloud Billing Budget API"
  ["binaryauthorization.googleapis.com"]="Binary Authorization API"
  ["blogger.googleapis.com"]="Blogger API v3"
  ["books.googleapis.com"]="Books API"
  ["bookstore.endpoints.endpoints-portal-demo.cloud.goog"]="Bookstore gRPC API"
  ["caldav.googleapis.com"]="CalDAV API"
  ["calendar-json.googleapis.com"]="Google Calendar API"
  ["carddav.googleapis.com"]="Google Contacts CardDAV API"
  ["chat.googleapis.com"]="Hangouts Chat API"
  ["chromeuxreport.googleapis.com"]="Chrome UX Report API"
  ["chromewebstore.googleapis.com"]="Chrome Web Store API"
  ["civicinfo.googleapis.com"]="Google Civic Information API"
  ["classroom.googleapis.com"]="Google Classroom API"
  ["cloudapis.googleapis.com"]="Google Cloud APIs"
  ["cloudasset.googleapis.com"]="Cloud Asset API"
  ["cloudbilling.googleapis.com"]="Cloud Billing API"
  ["cloudbuild.googleapis.com"]="Cloud Build API"
  ["clouddataprep.trifacta.com"]="Clouddataprep by Trifacta"
  ["clouddebugger.googleapis.com"]="Cloud Debugger API"
  ["clouderrorreporting.googleapis.com"]="Error Reporting API"
  ["cloudfunctions.googleapis.com"]="Cloud Functions API"
  ["cloudidentity.googleapis.com"]="Cloud Identity API"
  ["cloudiot.googleapis.com"]="Cloud IoT API"
  ["cloudkms.googleapis.com"]="Cloud Key Management Service (KMS) API"
  ["cloudlatencytest.googleapis.com"]="Cloud Network Performance Monitoring API"
  ["cloudprivatecatalog.googleapis.com"]="Cloud Private Catalog API"
  ["cloudprofiler.googleapis.com"]="Stackdriver Profiler API"
  ["cloudresourcemanager.googleapis.com"]="Cloud Resource Manager API"
  ["cloudscheduler.googleapis.com"]="Cloud Scheduler API"
  ["cloudsearch.googleapis.com"]="Cloud Search API"
  ["cloudshell.googleapis.com"]="Cloud Shell API"
  ["cloudtasks.googleapis.com"]="Cloud Tasks API"
  ["cloudtrace.googleapis.com"]="Cloud Trace API"
  ["cloudvideosearch.googleapis.com"]="Video Search API"
  ["cloudvolumesgcp-api.netapp.com"]="NetApp Cloud Volumes API"
  ["composer.googleapis.com"]="Cloud Composer API"
  ["compute.googleapis.com"]="Compute Engine API"
  ["computescanning.googleapis.com"]="Compute Scanning API"
  ["connectgateway.googleapis.com"]="Connect Gateway API"
  ["contacts.googleapis.com"]="Contacts API"
  ["container.googleapis.com"]="Kubernetes Engine API"
  ["containeranalysis.googleapis.com"]="Container Analysis API"
  ["containerregistry.googleapis.com"]="Container Registry API"
  ["containerscanning.googleapis.com"]="Container Scanning API"
  ["containerthreatdetection.googleapis.com"]="Container Threat Detection API"
  ["copresence.googleapis.com"]="Nearby Messages API"
  ["customsearch.googleapis.com"]="Custom Search API"
  ["datacatalog.googleapis.com"]="Google Cloud Data Catalog API"
  ["dataflow.googleapis.com"]="Dataflow API"
  ["datafusion.googleapis.com"]="Cloud Data Fusion API"
  ["datalabeling.googleapis.com"]="Data Labeling API"
  ["datamigration.googleapis.com"]="Database Migration API"
  ["dataproc.googleapis.com"]="Cloud Dataproc API"
  ["dataproc-control.googleapis.com"]="Cloud Dataproc Control API"
  ["datastore.googleapis.com"]="Cloud Datastore API"
  ["datastudio.googleapis.com"]="Data Studio API"
  ["deploymentmanager.googleapis.com"]="Cloud Deployment Manager V2 API"
  ["dfareporting.googleapis.com"]="Campaign Manager 360 API"
  ["dialogflow.googleapis.com"]="Dialogflow API"
  ["digitalassetlinks.googleapis.com"]="Digital Asset Links API"
  ["directions-backend.googleapis.com"]="Directions API"
  ["discovery.googleapis.com"]="API Discovery Service"
  ["displayvideo.googleapis.com"]="Display & Video 360 API"
  ["distance-matrix-backend.googleapis.com"]="Distance Matrix API"
  ["dlp.googleapis.com"]="Cloud Data Loss Prevention (DLP) API"
  ["dns.googleapis.com"]="Cloud DNS API"
  ["docs.googleapis.com"]="Google Docs API"
  ["documentai.googleapis.com"]="Cloud Document AI API"
  ["domains.googleapis.com"]="Cloud Domains API"
  ["domainsrdap.googleapis.com"]="Domains RDAP API"
  ["doubleclickbidmanager.googleapis.com"]="DoubleClick Bid Manager API"
  ["doubleclicksearch.googleapis.com"]="Search Ads 360 API"
  ["drive.googleapis.com"]="Google Drive API"
  ["driveactivity.googleapis.com"]="Drive Activity API"
  ["echo-api.endpoints.endpoints-portal-demo.cloud.goog"]="Endpoints Example"
  ["elasticsearch-service.gcpmarketplace.elastic.co"]="Elasticsearch Service on Elastic Cloud - Standard"
  ["elevation-backend.googleapis.com"]="Maps Elevation API"
  ["embeddedassistant.googleapis.com"]="Google Assistant API"
  ["endpoints.googleapis.com"]="Google Cloud Endpoints"
  ["endpointsportal.googleapis.com"]="Cloud Endpoints Portal"
  ["essentialcontacts.googleapis.com"]="Essential Contacts API"
  ["eventarc.googleapis.com"]="Eventarc API"
  ["factchecktools.googleapis.com"]="Fact Check Tools API"
  ["fcm.googleapis.com"]="Firebase Cloud Messaging API"
  ["fcmregistrations.googleapis.com"]="FCM Registration API"
  ["file.googleapis.com"]="Cloud Filestore API"
  ["firebase.googleapis.com"]="Firebase Management API"
  ["firebaseappdistribution.googleapis.com"]="Firebase App Distribution API"
  ["firebaseapptesters.googleapis.com"]="Firebase App Testers API"
  ["firebasedynamiclinks.googleapis.com"]="Firebase Dynamic Links API"
  ["firebaseextensions.googleapis.com"]="Firebase Extensions API"
  ["firebasehosting.googleapis.com"]="Firebase Hosting API"
  ["firebaseinappmessaging.googleapis.com"]="Firebase In-App Messaging API"
  ["firebaseinstallations.googleapis.com"]="Firebase Installations API"
  ["firebaseml.googleapis.com"]="Firebase ML API"
  ["firebasemods.googleapis.com"]="Firebase Mods API"
  ["firebasepredictions.googleapis.com"]="Firebase Predictions API"
  ["firebaseremoteconfig.googleapis.com"]="Firebase Remote Config API"
  ["firebaserules.googleapis.com"]="Firebase Rules API"
  ["firebasestorage.googleapis.com"]="Cloud Storage for Firebase API"
  ["firestore.googleapis.com"]="Cloud Firestore API"
  ["firewallinsights.googleapis.com"]="Firewall Insights API"
  ["fitness.googleapis.com"]="Fitness API"
  ["games.googleapis.com"]="Google Play Game Services"
  ["gamesconfiguration.googleapis.com"]="Google Play Game Services Publishing API"
  ["gameservices.googleapis.com"]="Game Services API"
  ["gamesmanagement.googleapis.com"]="Google Play Game Management"
  ["gcp.redisenterprise.com"]="Redis Enterprise"
  ["genomics.googleapis.com"]="Genomics API"
  ["geocoding-backend.googleapis.com"]="Geocoding API"
  ["geolocation.googleapis.com"]="Geolocation API"
  ["gkeconnect.googleapis.com"]="GKE Connect API"
  ["gkehub.googleapis.com"]="GKE Hub"
  ["gmail.googleapis.com"]="Gmail API"
  ["gmailpostmastertools.googleapis.com"]="Gmail Postmaster Tools API"
  ["googleads.googleapis.com"]="Google Ads API"
  ["googlecloudmessaging.googleapis.com"]="Cloud Messaging"
  ["groupsmigration.googleapis.com"]="Groups Migration API"
  ["groupssettings.googleapis.com"]="Groups Settings API"
  ["healthcare.googleapis.com"]="Cloud Healthcare API"
  ["homegraph.googleapis.com"]="HomeGraph API"
  ["iam.googleapis.com"]="Identity and Access Management (IAM) API"
  ["iamcredentials.googleapis.com"]="IAM Service Account Credentials API"
  ["iap.googleapis.com"]="Cloud Identity-Aware Proxy API"
  ["identitytoolkit.googleapis.com"]="Identity Toolkit API"
  ["indexing.googleapis.com"]="Indexing API"
  ["invoice.googleapis.com"]="Invoice"
  ["jobs.googleapis.com"]="Cloud Talent Solution API"
  ["kgsearch.googleapis.com"]="Knowledge Graph Search API"
  ["language.googleapis.com"]="Cloud Natural Language API"
  ["libraryagent.googleapis.com"]="Library Agent API"
  ["licensing.googleapis.com"]="Enterprise License Manager API"
  ["lifesciences.googleapis.com"]="Cloud Life Sciences API"
  ["localservices.googleapis.com"]="Local Services API"
  ["logging.googleapis.com"]="Cloud Logging API"
  ["managedidentities.googleapis.com"]="Managed Service for Microsoft Active Directory API"
  ["manufacturers.googleapis.com"]="Manufacturer Center API"
  ["maps-android-backend.googleapis.com"]="Maps SDK for Android"
  ["maps-backend.googleapis.com"]="Maps JavaScript API"
  ["maps-embed-backend.googleapis.com"]="Maps Embed API"
  ["maps-ios-backend.googleapis.com"]="Maps SDK for iOS"
  ["mediatranslation.googleapis.com"]="Media Translation API"
  ["memcache.googleapis.com"]="Cloud Memorystore for Memcached API"
  ["meshca.googleapis.com"]="Anthos Service Mesh Certificate Authority API"
  ["meshconfig.googleapis.com"]="Mesh Configuration API"
  ["meshtelemetry.googleapis.com"]="Mesh Telemetry API"
  ["migrate.googleapis.com"]="G Suite Migrate API"
  ["ml.googleapis.com"]="AI Platform Training & Prediction API"
  ["mlkit.googleapis.com"]="ML Kit API"
  ["mobilecrashreporting.googleapis.com"]="Mobile Crash Reporting API"
  ["monitoring.googleapis.com"]="Cloud Monitoring API"
  ["moviesanywhere.googleapis.com"]="Play Movies Anywhere API"
  ["multiclusteringress.googleapis.com"]="Multi Cluster Ingress API"
  ["multiclustermetering.googleapis.com"]="Multi cluster metering API"
  ["networkmanagement.googleapis.com"]="Network Management API"
  ["networkservices.googleapis.com"]="Network Services API"
  ["networktopology.googleapis.com"]="Network Topology API"
  ["notebooks.googleapis.com"]="Notebooks API"
  ["orgpolicy.googleapis.com"]="Organization Policy API"
  ["osconfig.googleapis.com"]="OS Config API"
  ["oslogin.googleapis.com"]="Cloud OS Login API"
  ["pagespeedonline.googleapis.com"]="PageSpeed Insights API"
  ["partners-json.googleapis.com"]="Google Partners API"
  ["payg-prod.gcpmarketplace.confluent.cloud"]="Confluent Cloud Service Prod"
  ["people.googleapis.com"]="People API"
  ["performanceparameters.googleapis.com"]="Android Performance Parameters API"
  ["photoslibrary.googleapis.com"]="Photos Library API"
  ["picker.googleapis.com"]="Google Picker API"
  ["places-backend.googleapis.com"]="Places API"
  ["playablelocations.googleapis.com"]="Playable Locations API"
  ["playcustomapp.googleapis.com"]="Google Play Custom App Publishing API"
  ["plus.googleapis.com"]="Google+ API"
  ["plusdomains.googleapis.com"]="Google+ Domains API"
  ["plushangouts.googleapis.com"]="Google+ Hangouts API"
  ["policytroubleshooter.googleapis.com"]="Policy Troubleshooter API"
  ["poly.googleapis.com"]="Poly API"
  ["privateca.googleapis.com"]="Certificate Authority API"
  ["prod-tt-sasportal.googleapis.com"]="SAS Portal API (Testing)"
  ["prod.cloud.datastax.com"]="DataStax Astra - Cassandra as a Service"
  ["prod.n4gcp.neo4j.io"]="Neo4j GCP Integration Service (Prod)"
  ["programmablesearchelement.googleapis.com"]="Programmable Search Element Paid API"
  ["pubsub.googleapis.com"]="Cloud Pub/Sub API"
  ["pubsublite.googleapis.com"]="Pub/Sub Lite API"
  ["realtime.googleapis.com"]="Realtime API"
  ["realtimebidding.googleapis.com"]="Real-time Bidding API"
  ["recommendationengine.googleapis.com"]="Recommendations AI"
  ["recommender.googleapis.com"]="Recommender API"
  ["redis.googleapis.com"]="Google Cloud Memorystore for Redis API"
  ["remotebuildexecution.googleapis.com"]="Remote Build Execution API"
  ["replicapool.googleapis.com"]="Compute Engine Instance Group Manager API"
  ["replicapoolupdater.googleapis.com"]="Compute Engine Instance Group Updater API"
  ["reseller.googleapis.com"]="Google Workspace Reseller API"
  ["resourceviews.googleapis.com"]="Compute Engine Instance Groups API"
  ["risc.googleapis.com"]="RISC API"
  ["roads.googleapis.com"]="Roads API"
  ["run.googleapis.com"]="Cloud Run Admin API"
  ["runtimeconfig.googleapis.com"]="Cloud Runtime Configuration API"
  ["safebrowsing-json.googleapis.com"]="Safe Browsing API (Legacy)"
  ["safebrowsing.googleapis.com"]="Safe Browsing API"
  ["sasportal.googleapis.com"]="SAS Portal API"
  ["script.googleapis.com"]="Apps Script API"
  ["searchconsole.googleapis.com"]="Google Search Console API"
  ["secretmanager.googleapis.com"]="Secret Manager API"
  ["securetoken.googleapis.com"]="Token Service API"
  ["securitycenter.googleapis.com"]="Security Command Center API"
  ["serviceconsumermanagement.googleapis.com"]="Service Consumer Management API"
  ["servicecontrol.googleapis.com"]="Service Control API"
  ["servicedirectory.googleapis.com"]="Service Directory API"
  ["servicemanagement.googleapis.com"]="Service Management API"
  ["servicenetworking.googleapis.com"]="Service Networking API"
  ["serviceusage.googleapis.com"]="Service Usage API"
  ["sheets.googleapis.com"]="Google Sheets API"
  ["shoppingcontent.googleapis.com"]="Content API for Shopping"
  ["siteverification.googleapis.com"]="Site Verification API"
  ["slides.googleapis.com"]="Google Slides API"
  ["smartdevicemanagement.googleapis.com"]="Smart Device Management API"
  ["sourcerepo.googleapis.com"]="Cloud Source Repositories API"
  ["source.googleapis.com"]="Cloud Source Repositories API"
  ["spanner.googleapis.com"]="Cloud Spanner API"
  ["speech.googleapis.com"]="Cloud Speech-to-Text API"
  ["sql-component.googleapis.com"]="Cloud SQL"
  ["sqladmin.googleapis.com"]="Cloud SQL Admin API"
  ["stackdriver.googleapis.com"]="Stackdriver API"
  ["static-maps-backend.googleapis.com"]="Maps Static API"
  ["storage-api.googleapis.com"]="Google Cloud Storage JSON API"
  ["storage-component.googleapis.com"]="Cloud Storage"
  ["storage.googleapis.com"]="Cloud Storage API"
  ["storagetransfer.googleapis.com"]="Storage Transfer API"
  ["street-view-image-backend.googleapis.com"]="Street View Static API"
  ["streetviewpublish.googleapis.com"]="Street View Publish API"
  ["sts.googleapis.com"]=" Security Token Service API"
  ["subscribewithgoogle.googleapis.com"]="Subscribe with Google Publication API"
  ["subscribewithgoogledeveloper.googleapis.com"]="Subscribe with Google Developer API"
  ["surveys.googleapis.com"]="Google Surveys API"
  ["tagmanager.googleapis.com"]="Tag Manager API"
  ["tasks.googleapis.com"]="Tasks API"
  ["testing.googleapis.com"]="Cloud Testing API"
  ["texttospeech.googleapis.com"]="Cloud Text-to-Speech API"
  ["threatdetection.googleapis.com"]="Threat Detection API"
  ["timezone-backend.googleapis.com"]="Time Zone API"
  ["toolresults.googleapis.com"]="Cloud Tool Results API"
  ["tpu.googleapis.com"]="Cloud TPU API"
  ["trafficdirector.googleapis.com"]="Traffic Director API"
  ["translate.googleapis.com"]="Cloud Translation API"
  ["travelpartner.googleapis.com"]="Travel Partner API"
  ["usercontext.googleapis.com"]="Awareness API"
  ["vault.googleapis.com"]="G Suite Vault API"
  ["vectortile.googleapis.com"]="Semantic Tile API"
  ["verifiedaccess.googleapis.com"]="Chrome Verified Access API"
  ["videointelligence.googleapis.com"]="Cloud Video Intelligence API"
  ["vision.googleapis.com"]="Cloud Vision API" 
  ["vmmigration.googleapis.com"]="VM Migration API"
  ["vmwareengine.googleapis.com"]="VMware Engine API"
  ["vpcaccess.googleapis.com"]="Serverless VPC Access API"
  ["walletobjects.googleapis.com"]="Google Pay Passes API"
  ["webfonts.googleapis.com"]="Web Fonts Developer API"
  ["webmasters.googleapis.com"]="Google Search Console API (Legacy)"
  ["websecurityscanner.googleapis.com"]="Web Security Scanner API"
  ["workflowexecutions.googleapis.com"]="Workflow Executions API"
  ["workflows.googleapis.com"]="Workflows API"
  ["youtube.googleapis.com"]="YouTube Data API v3"
  ["youtubeanalytics.googleapis.com"]="YouTube Analytics API"
  ["youtubereporting.googleapis.com"]="YouTube Reporting API"
  ["zync.googleapis.com"]="Zync Render API"
  )

  title1="공통"
  title2="GCP-SVC-AQ03"
  title3="로깅 모니터링(Stack Driver)"


  local check=$3
  local resource=$4
  local text=$5
  local loc_suc=$6
  local loc_fail=$7
  local loc_tot=$8

  loc_tot=0
  loc_suc=0
  loc_fail=0


  for command in $(gcloud services list --format="value(NAME)" 2>/dev/null)
  do
      readarray resultArray<<< "$command"
      NAME="${resultArray[0]}"
      NAME="${NAME//\"}"
      NAME="${NAME//[$'\t\r\n ']}"

      if [[ -v apis["$NAME"] ]]; then
          resource=${apis["$NAME"]}
          check="[양호]"
          loc_tot=$(( $(( ${loc_tot} +1 )) ))
          loc_suc=$(( $(( ${loc_suc} +1 )) ))
          add_suc_tot
          export title1 title2 title3 check resource text tot suc_cnt filename
          sh print.sh

      elif [[ ! -v apis["$NAME"] ]]; then
          check="[취약]"
          resource=$NAME
          loc_tot=$(( $(( ${loc_tot} +1 )) ))
          loc_fail=$(( $(( ${loc_fail} +1 )) ))
          add_fail_tot
          export title1 title2 title3 check resource text tot fail_cnt filename
          sh err_chk.sh
          sh print.sh
      fi
  done
echo "AQ03 검사 수 : ${loc_tot}"
echo "AQ03 양호 검사 수 : ${loc_suc}"
echo "AQ03 취약 검사 수 : ${loc_fail}"
}

function AQ04(){

  declare -A apis=(
["accessapproval.googleapis.com"]="Access Approval"
["notebooks.googleapis.com"]="AI Platform Notebooks"
["apigee.googleapis.com"]="Apigee"
["apigeeconnect.googleapis.com"]="Apigee Connect API"
["privateca.googleapis.com"]="Certificate Authority Service"
["ml.googleapis.com"]="Cloud AI Platform API"
["apigateway.googleapis.com"]="Cloud API Gateway API"
["cloudasset.googleapis.com"]="Cloud Asset API"
["automl.googleapis.com"]="Cloud AutoML API"
["cloudbilling.googleapis.com"]="Cloud Billing API"
["cloudbuild.googleapis.com"]="Cloud Build API"
["composer.googleapis.com"]="Cloud Composer API"
["dlp.googleapis.com"]="Cloud Data Loss Prevention (DLP) API"
["dataproc.googleapis.com"]="Cloud Dataproc API"
["datastore.googleapis.com"]="Cloud Datastore API"
["domains.googleapis.com"]="Cloud Domains API"
["cloudfunctions.googleapis.com"]="Cloud Functions API"
["healthcare.googleapis.com"]="Cloud Healthcare"
["iap.googleapis.com"]="Cloud Identity-Aware Proxy API"
["cloudiot.googleapis.com"]="Cloud IoT API"
["cloudkms.googleapis.com"]="Cloud Key Management Service (KMS) API"
["lifesciences.googleapis.com"]="Cloud Life Sciences API"
["logging.googleapis.com"]="Cloud Logging API"
["ml.googleapis.com"]="Cloud Machine Learning Engine"
["managedidentities.googleapis.com"]="Cloud Managed Microsoft AD API"
["memcache.googleapis.com"]="Cloud Memorystore for Redis API"
["osconfig.googleapis.com"]="Cloud OS Config API"
["pubsub.googleapis.com"]="Cloud Pub/Sub API"
["cloudresourcemanager.googleapis.com"]="Cloud Resource Manager API"
["run.googleapis.com"]="Cloud Run Admin API"
["runtimeconfig.googleapis.com"]="Cloud Runtime Configuration API"
["sourcerepo.googleapis.com"]="Cloud Source Repositories API"
["spanner.googleapis.com"]="Cloud Spanner API"
["sql-component.googleapis.com"]="Cloud SQL"
["tasks.googleapis.com"]="Cloud Tasks API"
["tpu.googleapis.com"]="Cloud TPU API"
["translate.googleapis.com"]="Cloud Translation API"
["compute.googleapis.com"]="Compute Engine API"
["datacatalog.googleapis.com"]="Customer Usage Data Processing API"
["datacatalog.googleapis.com"]="Data Catalog"
["dialogflow.googleapis.com"]="Dialogflow API"
["eventarc.googleapis.com"]="Eventarc API"
["firebase.googleapis.com"]="Firebase Management API"
["fcm.googleapis.com"]="Firebase Notifications Console"
["games.googleapis.com"]="Game Servers API"
["genomics.googleapis.com"]="Genomics API"
["gkeconnect.googleapis.com"]="GKE Connect API"
["gkehub.googleapis.com"]="GKE Hub"
["appengine.googleapis.com"]="Google App Engine Admin API"
["deploymentmanager.googleapis.com"]="Google Cloud Deployment Manager V2 API"
["dns.googleapis.com"]="Google Cloud DNS API"
["storage-component.googleapis.com"]="Google Cloud Storage"
["iam.googleapis.com"]="Identity and Access Management (IAM) API"
["identitytoolkit.googleapis.com"]="Identity Toolkit API"
["container.googleapis.com"]="Kubernetes Engine API"
["pubsublite.googleapis.com"]="Pub/Sub Lite API"
["recaptchaenterprise.googleapis.com"]="reCAPTCHA Enterprise API"
["recommendationengine.googleapis.com"]="Recommendations AI API"
["secretmanager.googleapis.com"]="Secret Manager API"
["securitycenter.googleapis.com"]="Security Command Center API"
["sts.googleapis.com"]="Security Token Service API"
["vpcaccess.googleapis.com"]="Serverless VPC Access API"
["servicebroker.googleapis.com"]="Service Broker API"
["servicedirectory.googleapis.com"]="Service Directory API"
["serviceusage.googleapis.com"]="Service Usage API"
["clouddebugger.googleapis.com"]="Stackdriver Debugger API"
["clouderrorreporting.googleapis.com"]="Stackdriver Error Reporting API"
["monitoring.googleapis.com"]="Stackdriver Monitoring API"
["cloudprofiler.googleapis.com"]="Stackdriver Profiler API"
["cloudtrace.googleapis.com"]="Stackdriver Trace API"
["transcoder.googleapis.com"]="Transcoder API"
["workflowexecutions.googleapis.com"]="Workflow Executions API"
)


local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
local loc_suc=$6
local loc_fail=$7
local loc_tot=$8

title1="공통"
title2="GCP-SVC-AQ04"
title3="감사 로깅"

  for command in $(jq '.[].asset.iamPolicy.policyBlob|select(.)|fromjson.auditConfigs |select(.) |.[].service' ${filename})
  do
      readarray resultArray<<< "$command"
      service="${resultArray[0]}"
      service="${service//\"}"
      service="${service//[$'\t\r\n ']}"
      echo "서비스 :"$service

      if [[ -z $command ]]; then
          check="[취약]"
          resource="감사 로깅 리소스 없음"
          text="-"
          add_fail_tot
          export title1 title2 title3 check resource text tot fail_cnt filename
          sh err_chk.sh
          sh print.sh
      fi

      if [[ $service=~"allServices" ]]; then
        check="[양호]"
        resource="71/71 모든 서비스에 대해서 로깅 모니터링 실행 중"
        text="취약 없음"
        tot=$(( $(( ${tot}+71 )) ))
        suc_cnt=$(( ${suc_cnt}+71 ))
        loc_suc=$(( ${loc_suc}+71 ))
        loc_tot=$(( ${loc_tot}+71 ))
        loc_fail=0
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh err_chk.sh
        sh print.sh
      fi

    break

      if [[ -v apis["$service"] ]]; then
          resource=${apis["$service"]}
          check="[양호]"
          add_suc_tot
          export title1 title2 title3 check resource text tot suc_cnt filename
          sh print.sh

      elif [[ ! -v apis["$service"] ]]; then
          check="[취약]"
          resource=$NAME
          add_fail_tot
          export title1 title2 title3 check resource text tot fail_cnt filename
          sh err_chk.sh
          sh print.sh
      fi
  done
echo "AQ04 검사 수 : ${loc_tot}"
echo "AQ04 양호 검사 수 : ${loc_suc}"
echo "AQ04 취약 검사 수 : ${loc_fail}"
}


function AQ05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-AQ05"
title2="KMS 키관리"

command=$(jq '.[].asset.resourceProperties.encryption|select(.)|fromjson|.defaultKmsKeyName|select(.)' ${filename})

for i in $command
do

    if [[ -n $command ]];
    then
        check="[양호]"
        resource=$i
        text="-"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh


    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 check resource text tot fail_cnt filename
        sh err_chk.sh
    fi
done
}


function AW05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(jq '.[].asset.iamPolicy.policyBlob |select(.) |fromjson |.bindings[] | select(.role=="roles/deploymentmanager.typeEditor")' ${filename})
title1="Cloud Deployment Manager"
title2="GCP-SVC-AW05"
title3="사용자 및 API 액세스 제어"

if [[ -n $command  ]]; then
        check="[양호]"
        resource="roles/deploymentmanager.typeEditor 설정 유저"
        text="설정 있음"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}


function AX01(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6


command=$(gcloud config get-value proxy/port)
title1="gcloud"
title2="GCP-SVC-AX01"
title3="방화벽 사용"

if [[ -n $command && $command!="unset" ]]; then
    check="[양호]"
    resource=$command
    text="-"
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh

elif [[ -z $command ]]; then
    check="[취약]"
    resource="리소스 없음"
    text="-"
    add_fail_tot
    export title1 title2 title3 check resource text tot fail_cnt filename
    sh err_chk.sh
    sh print.sh
fi
}

function AZ06(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6


title1="Compute Engine"
title2="GCP-SVC-AZ06"
title3="볼륨 암호화"
command=$(jq '.[].asset.resourceProperties.encryption|select(.)|fromjson|.defaultKmsKeyName|select(.)' ${filename})

echo $command

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}



function AZ09(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Compute Engine"
title2="GCP-SVC-AZ09"
title3="디스크 스냅샷"

com= jq -rc '.[].asset.securityCenterProperties|select(.resourceType=="google.compute.Snapshot")' ${filename} |
while read -r com; do
    SNPCHK="$(echo "$com" | jq '.resourceName')"

    if [[ -n $SNPCHK ]]; then
        check="[양호]"
        resource=$SNPCHK
        text="-"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh

    elif [[ -z $SNPCHK ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi
done
}

function AZ10(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Compute Engine"
title2="GCP-SVC-AZ10"
title3="VM 삭제방지"

com= jq -rc '.[].asset.resourceProperties | select(.deletionProtection)' ${filename} |
while read -r com; do
    DELCHK="$(echo "$com" | jq '.name')"

        if [[ -n $DELCHK ]]; then
            check="[양호]"
            resource=$DELCHK
            text="-"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh

        elif [[ -z $DELCHK ]]; then
            check="[취약]"
            resource="리소스 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi

    done
}


function AZ11(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Compute Engine"
title2="GCP-SVC-AZ11"
title3="보안 부팅"
command=$(jq '.[].asset.resourceProperties.shieldedInstanceConfig | select(.!= null) | fromjson |.enableSecureBoot' ${filename})

com= jq -rc '.[].asset.resourceProperties | select(.shieldedInstanceConfig)' ${filename} |
while read -r com; do
    RSC="$(echo "$com" | jq '.name')"
    SBCHK="$(echo "$com" | jq '.enableSecureBoot')"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ true ]]; then
            check="[양호]"
            resource=$command
            text="-"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh

        elif [[ ! $TFCHK =~ true ]]; then
            check="[취약]"
            resource="리소스 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh err_chk.sh
        sh print.sh
    fi
done
}


function AZ12(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Compute Engine"
title2="GCP-SVC-AZ12"
title3="vTPM 사용"

command=$(gcloud container clusters list --format="value(NAME,LOCATION)")

  for CLUSTERZONES in $(gcloud beta container clusters list --format="csv[no-heading](name,zone)")
  do
    IFS="," read CLUSTER LOCATION <<<"${CLUSTERZONES}"

    if [[ -z "$CLUSTER" ]]; then
        check="[정보]"
        resource="컨테이너 클러스터 설정없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi

    command2=$(gcloud container clusters describe ${CLUSTER} --zone ${LOCATION} --format=json |\
    jq '.nodeConfig.shieldedInstanceConfig.enableVtpm')
    for VtpmChk in $command2
    do
           
        if [[ "$VtpmChk"==null ]]; then
            check="[취약]"
            resource="${CLUSTER}"
            text="Vtpm 구성 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh

        elif [[ "$VtpmChk"==true ]]; then
            check="[양호]"
            resource="${CLUSTER}"
            text="Vtpm 구성 있음"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh err_chk.sh
            sh print.sh
        fi

    done
done
}


function AZ13(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Compute Engine"
title2="GCP-SVC-AZ13"
title3="무결성 모니터링"

command=$(gcloud container clusters list --format="value(NAME,LOCATION)")

  for CLUSTERZONES in $(gcloud beta container clusters list --format="csv[no-heading](name,zone)")
  do
    IFS="," read CLUSTER LOCATION <<<"${CLUSTERZONES}"

    if [[ -z "$CLUSTER" ]]; then
        check="[정보]"
        resource="컨테이너 클러스터 설정없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi

    command2=$(gcloud container clusters describe ${CLUSTER} --zone ${LOCATION} --format=json |\
    jq '.nodeConfig.shieldedInstanceConfig.enableIntegrityMonitoring')
    for MonitorChk in $command2
    do
        if [[ "$MonitorChk"==true ]]; then
            check="[양호]"
            resource="${CLUSTER}"
            text="보안 쉴드 구성 있음"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh err_chk.sh
            sh print.sh
            
        elif [[ -z "$MonitorChk" ]]; then
            check="[취약]"
            resource="무결성 모니터링 설정 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh

        elif [[ "$MonitorChk"==null ]]; then
            check="[취약]"
            resource="${CLUSTER}"
            text="무결성 모니터링 설정 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh

        fi
    done
done
}


function BC05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Run"
title2="GCP-SVC-BC05"
title3="서비스별 ID 사용"
command=$(jq '.[].asset.iamPolicy.policyBlob |select(.)|fromjson|.bindings[] |select(.role=="roles/run.serviceAgent")' ${filename})

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh

elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}


function BD07(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Functions"
title2="GCP-SVC-BD07"
title3="데이터 엑세스 감사로그"
command=$(jq '.[].asset.iamPolicy.policyBlob|select(.)|fromjson.auditConfigs |select(.) |.[] |select(.service=="cloudfunctions.googleapis.com")' ${filename})

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}

function BE06(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="App Engine"
title2="GCP-SVC-BE06"
title3="App Engine 방화벽"
com=$(gcloud app firewall-rules list --format="value(PRIORITY,ACTION)" 2>/dev/null)

for appfirewall in "$com"
do
    read PRIORITY ACTION <<<"${appfirewall}"
    echo -e "- PRIORITY:     ${PRIORITY}"
    echo -e "  ACTION:       ${ACTION}"

    if [[ -n $com && ${ACTION} =~ "DENY" ]]; then
        check="[양호]"
        resource="${ACTION}"
        text="PRIORITY : ${PRIORITY}"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh

    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi
done
}


function BG06(){

for CLUSTERZONES in $(gcloud beta container clusters list --format="csv[no-heading](name,zone,MASTER_VERSION)")
do
IFS="," read CLUSTER REGION MASTER_VERSION <<<"${CLUSTERZONES}"

read -a i <<<$(\
  gcloud container get-server-config \
  --region=$REGION \
  --format="json" \
  | jq --raw-output '
def to_gke_semver(o):
    capture("(?<major>[0-9]*).(?<minor>[0-9]*).(?<patch>[0-9]*)-gke.(?<gke>[0-9]*)");
def from_gke_semver(o):
    .major + "." + .minor + "." + .patch + "-gke." + .gke;
reduce (
    .validMasterVersions[] | to_gke_semver(.)
) as $this (
{
    "major":"0",
    "minor":"0",
    "patch": "0",
    "gke": "0"
};
if ($this.major|tonumber) > (.major|tonumber)
then . = $this
else (
    if ($this.major|tonumber) == (.major|tonumber)
    then (
        if ($this.minor|tonumber) > (.minor|tonumber)
        then . = $this
        else (
            if ($this.minor|tonumber) == (.minor|tonumber)
            then (
                if ($this.patch|tonumber) > (.patch|tonumber)
                then . = $this
                else (
                    if ($this.patch|tonumber) == (.patch|tonumber)
                    then (
                        if ($this.gke|tonumber) > (.gke|tonumber)
                        then . = $this
                        else .
                        end
                    )
                    else .
                    end
                )
                end
            )
            else .
            end
        )
        end
    )
    else .
    end
)
end
) | from_gke_semver(.)
')

title1="Google Kubernetes Engine(GKE)"
title2="GCP-SVC-BG06"
title3="Kubernetes 버전 최신 상태 유지"

for a in ${#i[@]};
do
    NUMBER=$(echo $i[@] | sed 's/[^0-9]*//g')
    NUMBER=${NUMBER:0:5}
        for master in ${#MASTER_VERSION[@]};
        do
            MASTER=$(echo $MASTER_VERSION[@] | sed 's/[^0-9]*//g')
            MASTER=${MASTER:0:5}
            if [[ $MASTER -ge $NUMBER ]];then
              check="[양호]"
              resource="${CLUSTER}"
              text="GKE 최신 버전 사용 중" 
              add_suc_tot
              export title1 title2 title3 check resource text tot suc_cnt filename
              sh print.sh
            else
               check="[취약]"
               resource="${CLUSTER}"
               text="마스터 버전 : ${MASTER_VERSION}이 최신 버전이 아님."
               add_fail_tot
               export title1 title2 title3 check resource text tot fail_cnt filename
               sh err_chk.sh
               sh print.sh
            fi
        done
    done
done
}


function BG07(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Google Kubernetes Engine(GKE)"
title2="GCP-SVC-BG07"
title3="마스터 승인 네트워크"


  for RETURNS in $(gcloud beta container clusters list --format="csv[no-heading](name,zone)")
  do
    IFS="," read NAME ZONE <<<"${RETURNS}"

    command2=$(gcloud container clusters describe ${NAME} --zone ${ZONE} --format=json | jq '.masterAuthorizedNetworksConfig.enabled')
    for MSCHK in $command2
    do
        if [[ -n $MSCHK && $MSCHK != "null" ]]; then
            check="[양호]"
            resource=$NAME
            text="-"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh

        elif [[ -z $MSCHK || $MSCHK == "null" ]]; then
            check="[취약]"
            resource=$NAME
            text="리소스 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi
    done

        if [[ -z $RETURNS ]]; then
                check="[정보]"
                resource="-"
                text="인스턴스 없음"
                add_info_tot
                export title1 title2 title3 check resource text tot info_cnt filename
                sh print.sh
        fi
done
}



function BG08(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Google Kubernetes Engine(GKE)"
title2="GCP-SVC-BG08"
title3="PodSecurityPolicy"
command=$(jq '.[].asset.resourceProperties.metadata|select(.)|fromjson.annotations.EnablePodSecurityPolicy|select(.)' ${filename})

  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"
    echo -e "TFCHK:    ${TFCHK}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ true ]]; then
            check="[양호]"
            resource=$command
            text="-"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh

        elif [[ ! $TFCHK =~ true ]]; then
            check="[취약]"
            resource="리소스 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi
done
}

function BG09(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Google Kubernetes Engine(GKE)"
title2="GCP-SEC-BG09"
title3="GKE Sandbox 워크로드 보안"

command=$(gcloud container clusters list --format="value(NAME,LOCATION)")

  for CLUSTERZONES in $(gcloud beta container clusters list --format="csv[no-heading](name,zone)")
  do
    IFS="," read CLUSTER LOCATION <<<"${CLUSTERZONES}"

    if [[ -z "$gvisorCheck" ]]; then
        check="[취약]"
        resource="보안 쉴드 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi


    command2=$(gcloud container clusters describe ${CLUSTER} --zone ${LOCATION} --format=json | grep -P "gvisor")
    for gvisorCheck in $command2
    do
        if [[ -n "$gvisorCheck" ]]; then
            check="[양호]"
            resource="${CLUSTER}"
            text="보안 쉴드 구성 있음"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh err_chk.sh
            sh print.sh

        elif [[ "$gvisorCheck"==null || -z "$gvisorCheck" ]]; then
            check="[취약]"
            resource="${CLUSTER}"
            text="보안 쉴드 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh

        fi
    done
done
}

function BG10(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

command=$(jq '.[].asset.resourceProperties.nodePools|select(.)|fromjson|.[]|.config|.metadata | ."disable-legacy-endpoints"' ${filename})
title1="Google Kubernetes Engine(GKE)"
title2="GCP-SVC-BG10"
title3="클러스터 메타데이터 보호"

  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ true ]]; then
            check="[양호]"
            resource="설정 있음"
            text="-"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh

        elif [[ ! $TFCHK =~ true ]]; then
            check="[취약]"
            resource="리소스 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi
    fi

    if [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi
done
}

function BG11(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Google Kubernetes Engine(GKE)"
title2="GCP-SEC-BG11"
title3="GKE 보안 노드"

command=$(gcloud container clusters list --format="value(NAME,LOCATION)")

  for CLUSTERZONES in $(gcloud beta container clusters list --format="csv[no-heading](name,zone)")
  do
    IFS="," read CLUSTER LOCATION <<<"${CLUSTERZONES}"

    command2=$(gcloud container clusters describe ${CLUSTER} --zone ${LOCATION} --format=json | jq '.shieldedNodes.enabled')
    for shieldCheck in $command2
    do
        if [[ "$shieldCheck"==true ]]; then
            check="[양호]"
            resource="${CLUSTER}"
            text="보안 쉴드 구성 있음"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh err_chk.sh
            sh print.sh


        elif [[ -z "$shieldCheck" ]]; then
            check="[취약]"
            resource="보안 쉴드 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh

        elif [[ "$shieldCheck"==null ]]; then
            check="[취약]"
            resource="${CLUSTER}"
            text="보안 쉴드 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh

        fi
    done
done
}



function BH06()
{
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Container Registry"
title2="GCP-SVC-BH06"
title3="인증 방식"

if [[ -f /$HOME/.docker/config.json ]]; then
     check="[양호]"
     resource="/$HOME/.docker/config.json"
     text="-"
     add_suc_tot
     export title1 title2 title3 check resource text tot suc_cnt filename
     sh print.sh

else check="[취약]"
     text="-"
     resource="리소스 액세스 설정 없음"
     add_fail_tot
     export title1 title2 title3 check resource text tot fail_cnt filename
     sh err_chk.sh
     sh print.sh
fi
}

function BH07(){

local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Container Registry"
title2="GCP-SVC-BH07"
title3="액세스 제어 구성"
command=$(gsutil list)

  for BUCKETLIST in $command
  do
    read -r bucketname <<<"${BUCKETLIST}"
          if [[ -z $bucketname ]]; then
              check="[정보]"
              resource="리소스 없음"
              text="-"
              add_info_tot
              export title1 title2 title3 check resource text tot info_cnt filename
              sh err_chk.sh
              sh print.sh
            fi

    command2=$(gsutil uniformbucketlevelaccess get ${bucketname})
    for uniform in $command2
    do
        if [[ "$uniform" =~ "False" ]]; then
            check="[취약]"
            resource=${bucketname}
            text="액세스 제어 구성 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        elif [[ "$uniform" =~ "True" ]]; then
            check="[양호]"
            resource=${bucketname}
            text="액세스 제어 구성 있음"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh
        fi
    done
done
}

function BH08(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Container Registry"
title2="GCP-SVC-BH08"
title3="Docker Hub 미러 보호"
command=$(docker system info | grep -A 1 'Registry Mirrors' 2>/dev/null)

if [[ -n $command ]]; then
    check="[양호]"
    resource=$command
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh

elif [[ -z $command ]]; then
    check="[취약]"
    resource="리소스 없음"
    text="-"
    add_fail_tot
    export title1 title2 title3 check resource text tot fail_cnt filename
    sh err_chk.sh
    sh print.sh
fi
}


function BU05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud CDN"
title2="GCP-SVC-BU05"
title3="서명된 URL 키 구성"
command=$(jq '.[].asset.resourceProperties.cdnPolicy|select(.)|fromjson|.signedUrlKeyNames[]' ${filename} 2>/dev/null)

if [[ -n $command ]]; then
    check="[양호]"
    resource=$command
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh

elif [[ -z $command ]]; then
    check="[취약]"
    resource="리소스 없음"
    text="-"
    add_fail_tot
    export title1 title2 title3 check resource text tot fail_cnt filename
    sh err_chk.sh
    sh print.sh
fi
}


function BV05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud DNS"
title2="GCP-SVC-BV05"
title3="DNSSEC 설정"
command=$(gcloud dns managed-zones list --format="csv[no-heading](name)")
  for DNSLIST in $command
  do
    read dnsname <<<"${DNSLIST}"
        if [[ -z $dnsname ]]; then
            check="[정보]"
            resource="리소스 없음"
            text="-"
            add_info_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi

    command2=$(gcloud dns managed-zones describe ${dnsname} --format=json | jq '.dnssecConfig.state')
    for stateChk in $command2
    do
        if [[ $stateChk =~ "off" ]]; then
            check="[취약]"
            resource=${dnsname}
            text="DNSSEC 설정 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh

        elif [[ $stateChk =~ "on" ]]; then
            check="[양호]"
            resource=${dnsname}
            text="DNSSEC 설정 있음"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh
        fi
    done
done
}


function BY05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Load Balancing"
title2="GCP-SVC-BY05"
title3="SSL 정책 사용"

command=$(gcloud compute ssl-certificates list --format="value(NAME)")
command2=$(gcloud compute url-maps list)

for i in $command
do

if [[ -n $command ]];
then
    check="[양호]"
    resource=$command
    text="-"
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh

elif [[ -z $command ]]; then
    check="[취약]"
    resource="리소스 없음"
    text="-"
    add_fail_tot
    export title1 title2 title3 check resource text tot fail_cnt filename
    sh err_chk.sh
    sh print.sh
fi
done

if [[ -z $command2 ]]; then
    check="[정보]"
    resource="로드밸런서 없음"
    text="-"
    add_info_tot
    export title1 title2 title3 check resource text tot info_cnt filename
    sh print.sh
    sh err_chk.sh
fi
}


function BZ05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud NAT"
title2="GCP-SVC-BZ05"
title3="NAT 연결 제한 시간"

command=$(gcloud compute routers list --format="csv[no-heading](NAME,REGION)")

  for ROUTERS in $command
  do
    IFS="," read router region <<<"${ROUTERS}"

    command2=$(gcloud compute routers nats list --router ${router} --region ${region} --format="value(NAME)")
    for NATS in $command2
    do
        IFS="," read nat <<<"${command2}"

        command3=$(gcloud compute routers nats describe ${nat} --router ${router} --region ${region} | grep 'icmpIdleTimeoutSec')
        for TOS in $command3
        do
            IFS="," read TOS <<<"${command3}"

            if [[ -z $TOS ]]; then
                check="[취약]"
                resource="-"
                text="NAT 연결 제한 시간 없음"
                add_fail_tot
                export title1 title2 title3 check resource text tot fail_cnt filename
                sh err_chk.sh
                sh print.sh

            elif [[ -n $TOS ]]; then
                check="[양호]"
                resource=${router}
                text=${region}
                add_suc_tot
                export title1 title2 title3 check resource text tot suc_cnt filename
                sh print.sh
            fi
        done
        if [[ -z $NATS ]]; then
            check="[정보]"
            resource="NAT Gateway 없음"
            text="-"
            add_info_tot
            export title1 title2 title3 check resource text tot info_cnt filename
            sh print.sh
            sh err_chk.sh
        fi
    done
    if [[ -z $ROUTERS ]]; then
        check="[정보]"
        resource="ROUTER 없음"
        text="-"
        add_info_tot
        export title1 title2 title3 check resource text tot info_cnt filename
        sh print.sh
    fi
done
}


function CA05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Storage"
title2="GCP-SVC-CA05"
title3="고급 보안 관리 구성"

url=$(gcloud compute url-maps list --format="csv[no-heading](NAME, DEFAULT_SERVICE)")

for configs in $url
do
IFS="," read name svc <<<"${configs}"

    if [[ -n $configs ]]; then
        check="[양호]"
        resource=${name}
        text=${svc}
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh

    elif [[ -z $configs ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi
done
}


function CB06(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Storage"
title2="GCP-SVC-CB06"
title3="객체 수명 주기 관리"

command=$(gsutil list)

  for BUCKETLIST in $command
  do
    read -r bucketname <<<"${BUCKETLIST}"
          if [[ -z $bucketname ]]; then
              check="[정보]"
              resource="리소스 없음"
              text="-"
              add_fail_tot
              export title1 title2 title3 check resource text tot fail_cnt filename
              sh err_chk.sh
              sh print.sh
            fi

    command2=$(gsutil lifecycle get ${bucketname})
    for version in $command2
    do
        if [[ $version == Suspended ]]; then
            check="[취약]"
            resource=${bucketname}
            text="수명 주기 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        elif [[ $version == Enabled ]]; then
            check="[양호]"
            resource=${bucketname}
            text="수명 주기 있음"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh
        fi
    done
done
}


function CB07(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Storage"
title2="GCP-SVC-CB07"
title3="객체 버전 관리 사용"

command=$(gsutil list)

  for BUCKETLIST in $command
  do
    read -r bucketname <<<"${BUCKETLIST}"
        if [[ -z $bucketname ]]; then
            check="[정보]"
            resource="리소스 없음"
            text="-"
            add_info_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi

    command2=$(gsutil versioning get ${bucketname})
    for version in $command2
    do
        if [[ $version == Suspended ]]; then
            check="[취약]"
            resource=${bucketname}
            text="버전 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh

        elif [[ $version == Enabled ]]; then
            check="[양호]"
            resource=${bucketname}
            text="버전 있음"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh
        fi
    done
done
}




function CB09(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Storage"
title2="GCP-SVC-CB09"
title3="HMAC 키 관리"

HMAC=$(gsutil hmac list)

    if [[ -n $HMAC ]]; then
        check="[양호]"
        resource="리소스 있음"
        text=""
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh

    elif [[ -z $HMAC ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi

}


function CD05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Filestore"
title2="GCP-SVC-CD05"
title3="NFS 파일 잠금"
command=$(gcloud compute firewall-rules list | grep '111\|2046\|4045')


if [[ -n $command ]]; then
    check="[양호]"
    resource="리소스 있음"
    text="-"
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh

elif [[ -z $command ]]; then
    check="[취약]"
    resource="리소스 없음"
    text="-"
    add_fail_tot
    export title1 title2 title3 check resource text tot fail_cnt filename
    sh err_chk.sh
    sh print.sh
fi
}


function CF06(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud SQL"
title2="GCP-SVC-CF06"
title3="연결 조직 정책 구성"

command=$(gcloud sql instances list --format="value(NAME)")
  for BUCKETS in $command
  do
    read -r bucketname <<<"${BUCKETS}"

        if [[ -z $bucketname  ]]; then
            check="[취약]"
            resource="리소스 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi

    command2=$(gcloud sql instances describe ${bucketname} | grep -P "authorizedNetwork")
    for network in $command2
    do
        if [[ -n $network ]]; then
            check="[양호]"
            resource=$command2
            text="-"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh
        fi
    done
        if [[ -z $network ]]; then
            check="[취약]"
            resource="연결 조직 정책 구성 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi
done
}


function CF07(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud SQL"
title2="GCP-SVC-CF07"
title3="SSL/TLS 인증서 구성"

command=$(gcloud sql instances list --format="value(NAME)")
  for BUCKETS in $command
  do
    read -r instancename <<<"${BUCKETS}"

        if [[ -z $instancename  ]]; then
            check="[정보]"
            resource="리소스 없음"
            text="-"
            add_info_tot
            export title1 title2 title3 check resource text tot info_cnt filename
            sh print.sh
        fi

    command2=$(gcloud beta sql ssl server-ca-certs list --instance ${instancename} --format="value(SHA1_FINGERPRINT)")
    for ssl in $command2
    do
        if [[ -n $ssl ]]; then
                check="[양호]"
                resource="${command2:20}"
                text="-"
                add_suc_tot
                export title1 title2 title3 check resource text tot suc_cnt filename
                sh print.sh

        elif [[ -z $ssl ]]; then
            check="[취약]"
            resource="연결 조직 정책 구성 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi
    done
done
}


function CF08(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud SQL"
title2="GCP-SVC-CF08"
title3="인스턴스 고가용성 설정"

command=$(gcloud sql instances list --format="value(NAME)")
  for INSTANCE in $command
  do
    read -r name <<<"${INSTANCE}"

      if [[ -z $name  ]]; then
          check="[정보]"
          resource="sql 인스턴스 없음"
          text="-"
          add_info_tot
          export title1 title2 title3 check resource text tot info_cnt filename
          sh print.sh
      fi

    command2=$(gcloud beta sql instances describe ${name} --format=json | jq '.settings.availabilityType')
    for availability in $command2
    do
      if [[ -z $availability ]]; then
              check="[취약]"
              resource="고가용성 설정 없음"
              text="-"
              add_info_tot
              export title1 title2 title3 check resource text tot info_cnt filename
              sh err_chk.sh
              sh print.sh
      fi
    done
    if [[ -n $availability ]]; then
        check="[양호]"
        resource=$name
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
    fi
done
}


function CF09(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud SQL"
title2="GCP-SVC-CF09"
title3="백업 및 관리"

command=$(gcloud sql instances list --format="value(NAME)")
  for INSTANCE in $command
  do
    read -r name <<<"${INSTANCE}"
    if [[ -z $name  ]]; then
            check="[정보]"
            resource="sql 인스턴스 없음"
            text="-"
            add_info_tot
            export title1 title2 title3 check resource text tot info_cnt filename
            sh print.sh
    fi

    command2=$(gcloud beta sql instances describe ${name} --format=json | jq '.settings.backupConfiguration')
    for backup in $command2
    do
        if [[ -z $backup ]]; then
                check="[취약]"
                resource="고가용성 설정 없음"
                text="-"
                add_fail_tot
                export title1 title2 title3 check resource text tot fail_cnt filename
                sh err_chk.sh
                sh print.sh
        fi
    done
            if [[ -n $backup ]]; then
                check="[양호]"
                resource=$resource
                add_suc_tot
                export title1 title2 title3 check resource text tot suc_cnt filename
                sh print.sh
            fi
done
}

function CF10(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud SQL"
title2="GCP-SVC-CF10"
title3="인스턴스 복원"

command=$(gcloud sql instances list --format="value(NAME)")
  for SQLLIST in $command
  do
    read -r name <<<"${SQLLIST}"
    if [[ -z $name ]]; then
        check="[취약]"
        resource="백업 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    fi

    command2=$(gcloud sql backups list --instance ${name} --format="value(ID)")
    if [[ -z $command2 ]]; then
        check="[취약]"
        resource=${name}
        text="백업 없음"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
    elif [[ -n $command2 ]]; then
        check="[양호]"
        resource=${name}
        text="백업 있음"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh
    fi
done
}

function CI06(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Bigtable"
title2="GCP-SVC-CI06"
title3="장애 조치 관리"

  for RETURNS in $(gcloud bigtable instances list --format="csv[no-heading](name)")
  do
    read NAME <<<"${RETURNS}"
    echo -e "NAME:    ${NAME}"

    command2=$(gcloud bigtable app-profiles list --instance=${NAME} --format=json | jq '.[].name')
    for APCHK in $command2
    do
        if [[ -n $APCHK  ]]; then
            check="[양호]"
            resource=$NAME
            text="-"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh

        elif [[ -z $APCHK ]]; then
            check="[취약]"
            resource="리소스 없음"
            text="-"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh

        fi

    done

        if [[ -z $RETURNS ]]; then
                check="[정보]"
                resource="인스턴스 없음"
                text="-"
                add_info_tot
                export title1 title2 title3 check resource text tot info_cnt filename
                sh print.sh
        fi
done
}


function CL05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Memorystore for Redis"
title2="GCP-SVC-CL05"
title3="Redis 버전 업그레이드"

command=$(gcloud redis regions list --format="value(NAME)")

  for regions in $command
  do
    command2=$(gcloud redis instances list --region ${regions} --format=json | jq '.[].redisVersion')
    for versionCheck in $command2
    do
        if [[ $versionCheck =~ "REDIS_5_0" ]]; then
            check="[양호]"
            resource=$versionCheck
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh

        elif [[ $versionCheck == "REDIS_4_0" ]]; then
            check="[취약]"
            resource="-"
            text="Redis 버전이 구버전임"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi
    done
done

    if [[ -z $command  ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
        fi
}


function CP06(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Data Fusion"
title2="GCP-SVC-CP06"
title3="비공개 인스턴스"

command=$(gcloud compute networks subnets list --format="csv[no-heading](name,privateIpGoogleAccess)")

  for RETURNS in $command
  do
    IFS="," read name TFCHK <<<"${RETURNS}"
    
    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ True ]]; then
            check="[양호]"
            resource=$name
            text="-"
            add_suc_tot
            export title1 title2 title3 check resource text tot suc_cnt filename
            sh print.sh

        elif [[ $TFCHK =~ False ]]; then
            check="[취약]"
            resource=$name
            text="리소스 없음"
            add_fail_tot
            export title1 title2 title3 check resource text tot fail_cnt filename
            sh err_chk.sh
            sh print.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[정보]"
        resource=$name
        text="서브넷 리소스 없음"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh

    fi
done
}


function CR06(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Dataproc"
title2="GCP-SVC-CR06"
title3="클러스터 관리"

command=$(gcloud compute regions list --format="value(NAME)")

  for regions in $command
  do
    command2=$(gcloud dataproc clusters list --region ${regions} --format="value(NAME)")
    for procchk in $command2
    do
            if [[ -z $procchk ]]; then
                check="[양호]"
                resource=$name
                text="-"
                add_suc_tot
                export title1 title2 title3 check resource text tot suc_cnt filename
                sh print.sh

            elif [[ -n $procchk ]]; then
                check="[취약]"
                resource="-"
                text="Dataproc 클러스터 사용 중"
                add_fail_tot
                export title1 title2 title3 check resource text tot fail_cnt filename
                sh err_chk.sh
                sh print.sh
            fi
    done
done
}

# function CT05(){

# local title1=$1
# local title2=$2
# local check=$3
# local resource=$4
# local text=$5

# command=$(jq '.[].asset.iamPolicy.policyBlob | fromjson | .bindings[]|.role' ${filename}  2>/dev/null)
# title1="GCP-SVC-CT05"
# title2="태그 템플릿 사용자 역할 부여"
# echo $command

# if [[ $command | grep "roles/datacatalog.tagTemplateUser" ]]; then
#         check="[양호]"
#         resource=$command
#         text="-"
#         echo "템플릿 사용자 : "$command
#         echo $title1,$title2,$check,$resource,$text
#         echo -n -e "\033[34m[양호]\033[0m"
#         tot=$(( $(( ${tot}+1 )) ))
#         suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
#         echo

#     elif [[ -z $command ]]; then
#         check="[취약]"
#         resource="-"
#         text="리소스 없음"
#         tot=$(( $(( ${tot}+1 )) ))
#         fail_cnt=$(( ${fail_cnt}+1 ))
#         export title1
#         export title2
#         export check
#         export resource
#         export text
#         export tot
#         export fail_cnt
#         echo -n -e "\033[33m[취약]\033[0m"
#         sh err_chk.sh
# fi
# }


function CU05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Life Sciences"
title2="GCP-SVC-CU05"
title3="장기 실행 작업 관리"

pipelines=$(gcloud beta lifesciences operations list --format="value(ID)")

if [[ -n $pipelines ]]; then
    check="[양호]"
    resource=$pipelines
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh

elif [[ -z $pipelines ]]; then
    check="[취약]"
    resource="리소스 없음"
    text="-"
    add_fail_tot
    export title1 title2 title3 check resource text tot fail_cnt filename
    sh err_chk.sh
    sh print.sh
fi
}


function DE05() {
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="AI Platform"
title2="GCP-SVC-DE05"
title3="고객 관리 암호화 키 사용"

cmd=$(jq '.[].asset.resourceProperties.encryption|select(.)|fromjson|.defaultKmsKeyName|select(.)' ${filename})

if [[ -n $cmd ]]; then
    check="[양호]"
    resource=$cmd
    text="-"
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh

elif [[ -z $cmd ]]; then
    check="[취약]"
    resource="리소스 없음"
    text="-"
    add_fail_tot
    export title1 title2 title3 check resource text tot fail_cnt filename
    sh err_chk.sh
    sh print.sh
fi
}


function DE06(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="AI Platform"
title2="GCP-SVC-DE06"
title3="학습시 VPC 서비스 제어 사용"
command=$(gcloud access-context-manager perimeters list)

if [[ -n $command ]]; then
    check="[양호]"
    resource=$($command)
    text="-"
    add_suc_tot
    export title1 title2 title3 check resource text tot suc_cnt filename
    sh print.sh

elif [[ -z $command ]]; then
    check="[취약]"
    resource="리소스 없음"
    text="-"
    add_fail_tot
    export title1 title2 title3 check resource text tot fail_cnt filename
    sh err_chk.sh
    sh print.sh
fi
}


function DM05(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud IoT Core"
title2="GCP-SVC-DM05"
title3="기기 사용자 인증 정보 확인"

  regions=(asia-east1 europe-west1 us-central1)

  for (( i = 0; i < ${#regions[@]}; i++ ))
  do
          for RETURNS in $(gcloud iot registries list --region ${regions[$i]} --format="value(ID)")
		  do
			read -r -a NAME <<<"${RETURNS}"
                command2=$(gcloud iot registries describe ${NAME} --region ${regions[$i]} --format=json | jq '.credentials[].publicKeyCertificate.certificate')
                if [[ -n $command2 ]]; then
                    check="[양호]"
                    resource=$NAME
                    text="-"
                    add_suc_tot
                    export title1 title2 title3 check resource text tot suc_cnt filename
                    sh print.sh

                elif [[ -z $command2 ]]; then
                    check="[취약]"
                    resource="리소스 없음"
                    text="-"
                    add_fail_tot
                    export title1 title2 title3 check resource text tot fail_cnt filename
                    sh err_chk.sh
                    sh print.sh
                fi

	          done

                if [[ -z $RETURNS ]]; then
                    check="[정보]"
                    resource="레지스트리 리소스 없음"
                    text="-"
                    add_fail_tot
                    export title1 title2 title3 check resource text tot fail_cnt filename
                    sh print.sh
    	        fi
		  done
}

function DN06(){
local title1=$1
local title2=$2
local title3=$3
local check=$4
local resource=$5
local text=$6

title1="Cloud Build"
title2="GCP-SVC-DN06"
title3="서비스 계정 권한 액세스"

command=$(jq '.[].asset.iamPolicy.policyBlob |select(.) |fromjson |.bindings[] | select(.role=="roles/container.developer")|.members[]' ${filename})

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        add_suc_tot
        export title1 title2 title3 check resource text tot suc_cnt filename
        sh print.sh

    elif [[ -z $command ]]; then
        check="[취약]"
        resource="리소스 없음"
        text="-"
        add_fail_tot
        export title1 title2 title3 check resource text tot fail_cnt filename
        sh err_chk.sh
        sh print.sh
fi
}


function add_suc_tot(){
    tot=$(( $(( ${tot} +1 )) ))
    suc_cnt=$(( $(( ${suc_cnt} +1 )) ))
}

function add_fail_tot(){
    tot=$(( $(( ${tot} +1 )) ))
    fail_cnt=$(( $(( ${fail_cnt} +1 )) ))
}

function add_info_tot(){
    tot=$(( $(( ${tot} +1 )) ))
    info_cnt=$(( $(( ${info_cnt} +1 )) ))
}

cmds=(  'AB01' 'AD01' 'AD04' 'AD05' 'AE01' 'AE02' 'AE03' 'AE04' 'AE05' 'AE06'
        'AE07' 'AF01' 'AG01' 'AH01' 'AI01' 'AJ02' 'AK01' 'AM02' 'AP01' 'AQ02'
        'AQ03' 'AX01' 'AZ06' 'AZ09' 'AZ10' 'AZ11' 'AZ12' 'AZ13' 'BC05' 'BD07' 
        'BE06' 'BG06' 'BG07' 'BG08' 'BG09' 'BG10' 'BG11' 'BH06' 'BH07' 'BH08' 
        'BU05' 'BV05' 'BY05' 'BZ05' 'CA05' 'CB06' 'CB07' 'CB09' 'CD05' 'CF06' 
        'CF07' 'CF08' 'CF09' 'CF10' 'CI06' 'CL05' 'CP06' 'CR06' 'CU05' 'DE05'
        'DE06' 'DM05' 'DN06')
for cmd in "${cmds[@]}"; do
    $cmd
done




echo "--------------------------------취약점 수집 종료--------------------------------"
echo "점검 종료시간 : " 
date "+%Y-%m-%d %H:%M:%S KST"
echo "###############################################"
echo "########### GCP 보안 체크리스트 점검 완료 ###########"
echo
echo "취약 항목 수 : "$fail_cnt/$tot
echo "총 취약 갯수 : "$fail_cnt

