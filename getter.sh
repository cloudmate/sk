tot=0
fail_cnt=0
suc_cnt=0


function AA01(){

  local title1=$1
  local title2=$2
  local check=$3
  local resource=$4
  local text=$5
  title1="GCP-SEC-AA01"
  title2="패스워드 복잡성 설정"

  command1=`cat /etc/login.defs | grep PASS_MIN_DAYS | awk '{print $2}' | sed '1d'`
  command2=`cat /etc/login.defs | grep PASS_WARN_AGE | awk '{print $2}' | sed '1d'`

  echo "    ==> 최소 사용 시간          :   `cat /etc/login.defs | grep PASS_MIN_DAYS | awk '{print $2}' | sed '1d'`일"
  echo "    ==> 기간 만료 경고 기간(일) :   `cat /etc/login.defs | grep PASS_WARN_AGE | awk '{print $2}' | sed '1d'`일"

  if [[ -n $command1&&$command2 ]]; then
       check="[양호]"
       text="-"
       echo $title1,$title2,$check
       echo -n -e "\033[34m[양호]\033[0m"
       tot=$(( $(( ${tot}+1 )) ))
       suc_cnt=$(( ${suc_cnt}+1 ))
       echo

  else echo -n -e "\033[31m[취약]\033[0m"
       check="[취약]"
       text="설정 없음"
       tot=$(( $(( ${tot}+1 )) ))
       fail_cnt=$(( ${fail_cnt}+1 ))
       echo
       export title1
       export title2
       export check
       export resource
       export text
       export tot
       export fail_cnt
       echo -n -e "\033[33m[취약]\033[0m"
       sh err_chk.sh
  fi


}

function AA02(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AA02"
title2="패스워드 최소길이 설정"

command=`cat /etc/login.defs | grep PASS_MIN_LEN | awk '{print $2}' | sed '1d'`
echo "    ==> 최소 길이               :   `cat /etc/login.defs | grep PASS_MIN_LEN | awk '{print $2}' | sed '1d'`글자"

if [[ -n $command ]]; then
     check="[양호]"
     text="-"
     echo $title1,$title2,$check
     echo -n -e "\033[34m[양호]\033[0m"
     tot=$(( $(( ${tot}+1 )) ))
     suc_cnt=$(( ${suc_cnt}+1 ))
     echo

else echo -n -e "\033[31m[취약]\033[0m"
     check="[취약]"
     text="최소길이 설정 없음"
     tot=$(( $(( ${tot}+1 )) ))
     fail_cnt=$(( ${fail_cnt}+1 ))
     echo
     export title1
     export title2
     export check
     export resource
     export text
     export tot
     export fail_cnt
     echo -n -e "\033[33m[취약]\033[0m"
     sh err_chk.sh
fi

}

function AA03(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AA02"
title2="패스워드 최소길이 설정"


PP=`ls -l /etc/passwd | awk {'print $1'}`
PO=`ls -l /etc/passwd | awk {'print $3'}`
PG=`ls -l /etc/passwd | awk {'print $4'}`

if [ $PP = -r--r--r--. ]
	then
		echo "    ==> [안전] 권한   : " $PP
    check="[양호]"
    text="-"
    echo $title1,$title2,$check
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( ${suc_cnt}+1 ))
else
	if [ $PP = -rw-r--r--. ]
		then
			echo "    ==> [안전] 권한   : " $PP
      check="[양호]"
      text="-"
      echo $title1,$title2,$check
      echo -n -e "\033[34m[양호]\033[0m"
      tot=$(( $(( ${tot}+1 )) ))
      suc_cnt=$(( ${suc_cnt}+1 ))
		else
			echo "    ==> [취약] 권한   : " $PP
      check="[취약]"
      text="권한 설정에 취약점 발견"
      tot=$(( $(( ${tot}+1 )) ))
      fail_cnt=$(( ${fail_cnt}+1 ))
      echo
      export title1
      export title2
      export check
      export resource
      export text
      export tot
      export fail_cnt
      echo -n -e "\033[33m[취약]\033[0m"
      sh err_chk.sh
	fi
fi

if [ $PO = root ]
	then
		echo "    ==> [안전] 소유자 : " $PO
    check="[양호]"
    text="소유자 권한 양호"
    echo $title1,$title2,$check
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( ${suc_cnt}+1 ))
	else
		echo "    ==> [취약] 소유자 : " $PO
    check="[취약]"
    text="소유자 권한 취약"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    echo
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi

if [ $PG = root ]
	then
		echo "    ==> [안전] 그룹   : " $PO
    check="[양호]"
    text="-"
    echo $title1,$title2,$check
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( ${suc_cnt}+1 ))
	else
		echo "    ==> [취약] 그룹   : " $PO
    check="[취약]"
    text="소유자 권한 취약"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    echo
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi

}

function AA04(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AA04"
title2="패스워드 최대 사용기간 설정"

command=`cat /etc/login.defs | grep PASS_MAX_DAYS | awk '{print $2}' | sed '1d'`
echo "    ==> 최대 사용기간             :   `cat /etc/login.defs | grep PASS_MAX_DAYS | awk '{print $2}' | sed '1d'`일"

if [[ -n $command ]]; then
     check="[양호]"
     text="-"
     echo $title1,$title2,$check
     echo -n -e "\033[34m[양호]\033[0m"
     tot=$(( $(( ${tot}+1 )) ))
     suc_cnt=$(( ${suc_cnt}+1 ))
     echo "최대 사용 기간          :   `cat /etc/login.defs | grep PASS_MAX_DAYS | awk '{print $2}' | sed '1d'`일"
     echo

else echo -n -e "\033[31m[취약]\033[0m"
     check="[취약]"
     text="리소스 없음"
     tot=$(( $(( ${tot}+1 )) ))
     fail_cnt=$(( ${fail_cnt}+1 ))
     echo
     export title1
     export title2
     export check
     export resource
     export text
     export tot
     export fail_cnt
     echo -n -e "\033[33m[취약]\033[0m"
     sh err_chk.sh
fi

}

function AA05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AA05"
title2="불필요한 계정 제거"

AA05=$(gcloud auth list --format="json" | jq '.[].status')

  if [ $AA05 = ACTIVE ]; then
        check="[양호]"
        resource=$AA05
        text="-"
        echo $title1,$title2,$check
        echo "계정 리소스 : "$AA05
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( ${suc_cnt}+1 ))
        echo

    elif [[ -z $command2 ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}

function AA06(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AA06"
title2="권한 그룹 관리"

AA06=$(gcloud organizations list --format=json | jq '.[].lifecycleState')
  if [ $AA06 != INACTIVE ]; then
        check="[양호]"
        text="-"
        echo $title1,$title2,$check
        echo "권한 그룹 관리 : "$AA06
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( ${suc_cnt}+1 ))
        echo

    elif [[ -z $command2 ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AB02(){


local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5



command=$(jq '.[].asset.resourceProperties.primary |select(.) |fromjson |.state' ${filename})
title1="GCP-SEC-AB02"
title2="TCP 전달을 위한 Cloud IAP 사용"

echo $command
  echo -e "TFCHK:    ${TFCHK}"

  if [[ -n $TFCHK  ]]; then
      if [[ $TFCHK =~ ENABLED ]]; then
          check="[양호]"
          resource=$command
          text="-"
          echo $title1,$title2
          echo "리소스: - "
          echo -n -e "\033[34m[양호]\033[0m"
          tot=$(( $(( ${tot}+1 )) ))
          suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
          echo

      elif [[ $TFCHK =~ DESTROYED ]]; then
          check="[취약]"
          resource="-"
          text="리소스 없음"
          tot=$(( $(( ${tot}+1 )) ))
          fail_cnt=$(( ${fail_cnt}+1 ))
          export title1
          export title2
          export check
          export resource
          export text
          export tot
          export fail_cnt
          echo -n -e "\033[33m[취약]\033[0m"
          sh err_chk.sh
      fi

  elif [[ -z $TFCHK ]]; then
      check="[취약]"
      resource="-"
      text="리소스 없음"
      tot=$(( $(( ${tot}+1 )) ))
      fail_cnt=$(( ${fail_cnt}+1 ))
      export title1
      export title2
      export check
      export resource
      export text
      export tot
      export fail_cnt
      echo -n -e "\033[33m[취약]\033[0m"
      sh err_chk.sh
  fi
done
}

function AD01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


command=$(jq '.[].asset.resourceProperties.primary |select(.) |fromjson |.state' ${filename})
title1="GCP-SEC-AD01"
title2="키 버전 설정 및 중지"

  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"
    echo -e "TFCHK:    ${TFCHK}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ ENABLED ]]; then
            check="[양호]"
            resource=$command
            text="-"
            echo $title1,$title2
            echo "리소스: - "
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ $TFCHK =~ DESTROYED ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
    fi
done
}


function AD02(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


command=$(jq '.[].asset.resourceProperties.primary |select(.) |fromjson |.state' {$filename})
title1="GCP-SEC-AD02"
title2="키 버전 폐기"

echo $command


  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"
    echo -e "TFCHK:    ${TFCHK}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ ENABLED ]]; then
            check="[양호]"
            resource=$command
            text="-"
            echo $title1,$title2
            echo "리소스: - "
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ ! $TFCHK =~ ENABLED ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
    fi
done
}


function AD04(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AD04"
title2="Cloud HSM 클러스터 관리"

if [[ -n $(jq '.[].asset.resourceProperties|select(.protectionLevel=="HSM")' ${filename}) ]]; then
    check="[양호]"
    text="-"
    echo $title1,$title2,$check
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( ${suc_cnt}+1 ))
    echo "총 검사수 : $tot"
    echo "성공 검사수 : $suc_cnt"

elif [[ -z $(jq '.[].asset.resourceProperties|select(.protectionLevel=="HSM")' ${filename}) ]]; then
    check="[취약]"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    echo "총 검사수 : $tot"
    echo "성공 검사수 : $fail_cnt"
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}

function AD05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AD05"
title2="Cloud EKM 키 관리"


if [[ -n $(jq '.[].asset.resourceProperties|select(.protectionLevel=="EKM")' ${filename}) ]]; then
        check="[양호]"
        text="-"
        echo $title1,$title2,$check
        echo "Cloud EKM 키 관리 :"`jq .[].asset.resourceProperties|select(.protectionLevel=="EKM")`
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        #suc_cnt=$(( ${suc_cnt}+1 ))
        echo

    elif [[ -z $(jq '.[].asset.resourceProperties|select(.protectionLevel=="EKM")' ${filename}) ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AE01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AE01"
title2="네트워크 대역 분"


if [[ $(gcloud compute networks subnets list --format="value(NAME)" | wc -l) -gt 0 ]]; then
        check="[양호]"
        text="-"
        echo $title1,$title2,$check
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        #suc_cnt=$(( ${suc_cnt}+1 ))
        echo

        echo $title1,$title2,$check
        echo "네트워크 대역 분 :"`gcloud compute networks subnets list --format="csv(NAME,REGION,NETWORK,RANGE)"`
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        #suc_cnt=$(( ${suc_cnt}+1 ))
        echo


    elif [[ -z $command2 ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AE02(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(jq '.[].asset.resourceProperties|select(.) |.sourceRanges |select(.)|fromjson |.[]' ${filename})
title1="GCP-SEC-AE02"
title2="방화벽 규칙 특정IP 제한"

for returns in $command
do
	echo $returns

if [[ -n $returns  ]]; then
        check="[양호]"
        resource=$returns
        text="-"
        echo $title1,$title2
        echo "리소스: "$returns
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo
		fi
done

    if [[ -z $command ]]; then
        check="[정보]"
        resource="-"
        text="방화벽 규칙 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AE03(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AE03"
title2="패킷 미러링"

command=$(gcloud compute packet-mirrorings list --format="value(NAME)")

if [[ -n $command ]]; then
        check="[양호]"
        text=$command
        echo $title1,$title2,$text,$check
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( ${suc_cnt}+1 ))
        echo

    elif [[ -z $(gcloud compute networks subnets list --format="value(NAME)" | wc -l) ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}

function AE04(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SEC-AE04"
title2="IP 보안정책 접근 제어"

command=$(jq '.[].asset.resourceProperties|select(.) |.sourceRanges |select(.)|fromjson|.[]' ${filename})

  for ips in $command
  do
    echo -e "ips:    ${ips}"

        if [[ -n $ips ]]; then
          echo $title1,$title2
          echo -n -e "\033[34m[양호]\033[0m"
          tot=$(( $(( ${tot}+1 )) ))
          suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
          name=$resource
          echo
          export name


        elif [[ -z $ips ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo $title, $title2, $check, $text
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi
done
}

function AE05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


command=$(jq '.[].asset.resourceProperties.rule|select(.)|fromjson |.[]' {$filename})
title1="GCP-SEC-AE05"
title2="클라우드 보안 정책 모니터링"


if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        echo $title1,$title2
        echo "리소스: "$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo
elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}
AE05


###########AE

function AE06(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AE06"
title2="인터넷 연결 차단"


if [ $(gcloud compute networks subnets list --format="value(NAME)" | wc -l) -gt 0 ]; then
        check="[양호]"
        text="-"
        echo $title1,$title2,$check
        echo "인터넷 연결 차단 :"`gcloud compute networks subnets list --format="csv(NAME,REGION,NETWORK,RANGE)"`
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( ${suc_cnt}+1 ))
        echo

    elif [[ -z $(gcloud compute networks subnets list --format="value(NAME)" | wc -l) ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}

function AE07(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(gcloud compute firewall-rules list --format="value(NAME)")
title1="GCP-SEC-AE07"
title2="최소한의 리소스 연결"

if [[ -n $command ]]; then
        check="[양호]"
        resource="방화벽 설정 있음"
        echo $title1,$title2,$resource
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo

elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}

function AF01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(gcloud beta compute security-policies list --format="value(NAME)")
title1="GCP-SEC-AF01"
title2="DOS 공격에 대한 방어 모니터링"

if [[ -n $command ]]; then
        check="[양호]"
        resource="방화벽 설정 있음"
        echo $title1,$title2,$resource
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo

elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
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
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AG01"
title2="DLP 서비스 경계 설정"

if [[ $(gcloud access-context-manager perimeters list) -gt 0 ]]; then
        check="[양호]"
        text="-"
        echo $title1,$title2,$check
        echo "DLP 서비스 경계 :"`gcloud access-context-manager perimeters list`
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( ${suc_cnt}+1 ))
        echo

    elif [[ -z $(gcloud access-context-manager perimeters list) ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AH01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AH01"
title2="네트워크 토폴로지"

command=$(gcloud services list --enabled --format=json | grep -P "topology")

if [[ -n $command ]]; then
        check="[양호]"
        text="-"
        echo $title1,$title2,$check
        echo "네트워크 토폴로지 :"`gcloud services list --enabled --format=json | grep -P "topology"`
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( ${suc_cnt}+1 ))
        echo

    elif [[ -z $command ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AI01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AI01"
title2="VPC 흐름 로그 설정"

command=$(gcloud compute networks subnets list --format="value(name)" --filter="enableFlowLogs:true")

if [[ -n $command ]]; then
        check="[양호]"
        text="-"
        echo $title1,$title2,$check
        echo "DLP 서비스 경계 :"$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( ${suc_cnt}+1 ))
        echo


    elif [[ -z $command ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}

function AJ02(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AJ02"
title2="Security Command Center API 설정"

command=$(gcloud services list --enabled --format=json | grep -P "securitycenter.googleapis.com")

if [[ -n $command ]]; then
        check="[양호]"
        text="-"
        echo $title1,$title2,$check
        echo "Security Command Center API :"$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( ${suc_cnt}+1 ))
        echo


    elif [[ -z $command ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AK01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
title1="GCP-SEC-AK01"
title2="보안 명령 센터 설정"

ORG=$(gcloud organizations list --format="value(ID)")
command=$(gcloud scc sources describe organizations/$ORG --source-display-name='Security Health Analytics')

if [[ -n $command ]]; then
        check="[양호]"
        text="-"
        echo $title1,$title2,$check
        echo "Security Command Center API :"$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( ${suc_cnt}+1 ))
        echo


    elif [[ -z $command ]]; then
        check="[취약]"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        echo
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AM02(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

AM02="gcloud logging logs list"
title1="GCP-SEC-AM02"
title2="VPC 흐름 로그 설정"

if [[ -n $($AM02 --format=json | grep -P "/logs/cloudaudit.googleapis.com%2Factivity") ]]; then
    check="[양호]"
    text="-"
    echo $title1,$title2
    echo -n -e "\033[34m 2Factivity : [양호]\033[0m\n"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( ${suc_cnt}+1 ))

else echo -n -e "\033[31m 2Factivity : [리소스 없음]\033[0m\n"
    check="[취약]"
    text="2Factivity : [리소스 없음]"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    echo
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi

if [[ -n $($AM02 --format=json | grep -P "/logs/cloudaudit.googleapis.com%2Fdata_access") ]]; then
   echo -n -e "\033[34m 2Fdata_access : [양호]\033[0m\n"
else echo -n -e "\033[31m 2Fdata_access : [리소스 없음]\033[0m\n"
  check="[취약]"
  text="2Fdata_access : [리소스 없음]"
  tot=$(( $(( ${tot}+1 )) ))
  fail_cnt=$(( ${fail_cnt}+1 ))
  echo
  export title1
  export title2
  export check
  export resource
  export text
  export tot
  export fail_cnt
  echo -n -e "\033[33m[취약]\033[0m"
  sh err_chk.sh
fi

if [[ -n $($AM02 --format=json | grep -P "/logs/cloudaudit.googleapis.com%2Fsystem_event") ]]; then
   echo -n -e "\033[34m 2Fsystem_event : [양호]\033[0m\n"
else echo -n -e "\033[31m 2Fsystem_event : [리소스 없음]\033[0m"
  check="[취약]"
  text="2Fsystem_event : [리소스 없음]"
  tot=$(( $(( ${tot}+1 )) ))
  fail_cnt=$(( ${fail_cnt}+1 ))
  echo
  export title1
  export title2
  export check
  export resource
  export text
  export tot
  export fail_cnt
  echo -n -e "\033[33m[취약]\033[0m"
  sh err_chk.sh
fi
echo
}



function AP01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-AP01"
title2="웹 보안 스캐너"
command=$(gcloud alpha web-security-scanner scan-configs list --format="value(displayName)" 2>/dev/null)

for scanner in $command
do
  echo -e "스캐너:    ${scanner}"
done


if [[ -n $command ]]; then
        check="[양호]"
        echo $title1,$title2,$check
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo

    elif [[ -z $command ]]; then
         check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}

function AQ01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-AQ01"
title2="사용자 액세스 제어(IAM)"
PROJECT=$(gcloud config get-value project)

ROLES=("roles/owner" "roles/accessapproval.approver" "roles/accesscontextmanager.gcpAccessAdmin" "roles/accesscontextmanager.policyAdmin"
 "roles/apigateway.admin" "roles/apigee.admin" "roles/apigee.developerAdmin" "roles/apigee.synchronizerManager" "roles/apigeeconnect.Admin" "roles/appengine.appAdmin"
 "roles/appengine.serviceAdmin" "roles/artifactregistry.admin" "roles/artifactregistry.repoAdmin" "roles/assuredworkloads.admin" "roles/automl.admin" "roles/bigquery.admin"
 "roles/bigquery.connectionAdmin" "roles/bigquery.dataOwner" "roles/bigquery.resourceAdmin" "roles/bigtable.admin" "roles/billing.admin" "roles/billing.projectManager"
 "roles/binaryauthorization.attestorsAdmin" "roles/binaryauthorization.policyAdmin" "roles/chat.owner" "roles/cloudasset.owner" "roles/datafusion.admin" "roles/cloudfunctions.admin"
 "roles/iap.admin" "roles/iap.settingsAdmin" "roles/cloudiot.admin" "roles/cloudjobdiscovery.admin" "roles/cloudkms.admin" "roles/consumerprocurement.entitlementManager"
 "roles/consumerprocurement.orderAdmin" "roles/cloudmigration.inframanager" "roles/vmmigration.admin" "roles/cloudprivatecatalogproducer.admin" "roles/cloudprivatecatalogproducer.manager"
 "roles/cloudscheduler.admin" "roles/servicebroker.admin" "roles/servicebroker.operator" "roles/cloudsql.admin" "roles/cloudtasks.admin"
 "roles/cloudtasks.queueAdmin" "roles/cloudtrace.admin" "roles/cloudtranslate.admin" "roles/workflows.admin" "roles/codelabapikeys.admin" "roles/composer.admin" "roles/composer.environmentAndStorageObjectAdmin"
 "roles/compute.admin" "roles/compute.instanceAdmin" "roles/compute.instanceAdmin.v1" "roles/compute.loadBalancerAdmin" "roles/compute.networkAdmin" "roles/compute.orgSecurityPolicyAdmin"
 "roles/compute.orgSecurityResourceAdmin" "roles/compute.packetMirroringAdmin" "roles/compute.securityAdmin" "roles/compute.storageAdmin" "roles/compute.xpnAdmin" "roles/osconfig.assignmentAdmin"
 "roles/osconfig.osConfigAdmin" "roles/container.admin" "roles/container.clusterAdmin" "roles/containeranalysis.admin" "roles/datacatalog.admin" "roles/datacatalog.categoryAdmin"
 "roles/datacatalog.entryGroupOwner" "roles/datacatalog.entryOwner" "roles/dataflow.admin" "roles/datalabeling.admin" "roles/datamigration.admin" "roles/dataproc.admin"
 "roles/datastore.importExportAdmin" "roles/datastore.indexAdmin" "roles/datastore.owner" "roles/dialogflow.admin" "roles/dlp.admin" "roles/dns.admin"
 "roles/endpoints.portalAdmin" "roles/errorreporting.admin" "roles/eventarc.admin" "roles/firebase.admin" "roles/firebase.analyticsAdmin" "roles/firebase.developAdmin"
 "roles/firebase.growthAdmin" "roles/firebase.qualityAdmin" "roles/cloudconfig.admin" "roles/cloudtestservice.testAdmin" "roles/firebaseabt.admin" "roles/firebaseappdistro.admin"
 "roles/firebaseauth.admin" "roles/firebasecrashlytics.admin" "roles/firebasedatabase.admin" "roles/firebasedynamiclinks.admin" "roles/firebasehosting.admin" "roles/firebaseinappmessaging.admin"
 "roles/firebaseml.admin" "roles/firebasenotifications.admin" "roles/firebaseperformance.admin" "roles/firebasepredictions.admin" "roles/firebaserules.admin" "roles/gameservices.admin"
 "roles/genomics.admin" "roles/gkehub.admin" "roles/gkehub.gatewayAdmin" "roles/healthcare.annotationEditor" "roles/healthcare.annotationStoreAdmin" "roles/healthcare.consentArtifactAdmin"
 "roles/healthcare.consentStoreAdmin" "roles/healthcare.datasetAdmin" "roles/healthcare.dicomStoreAdmin" "roles/healthcare.fhirStoreAdmin" "roles/healthcare.hl7V2StoreAdmin"
 "roles/iam.securityAdmin" "roles/iam.organizationRoleAdmin" "roles/iam.roleAdmin" "roles/iam.serviceAccountAdmin" "roles/iam.serviceAccountKeyAdmin"
 "roles/iam.workloadIdentityPoolAdmin" "roles/lifesciences.admin" "roles/logging.admin" "roles/managedidentities.admin" "roles/managedidentities.domainAdmin"
 "roles/memcache.admin" "roles/ml.admin" "roles/ml.jobOwner" "roles/ml.modelOwner" "roles/ml.operationOwner" "roles/monitoring.admin" "roles/monitoring.editor"
 "roles/networkmanagement.admin" "roles/notebooks.admin" "roles/notebooks.legacyAdmin" "roles/axt.admin" "roles/orgpolicy.policyAdmin" "roles/aiplatform.admin"
 "roles/aiplatform.featurestoreAdmin" "roles/dataprocessing.admin" "roles/domains.admin" "roles/essentialcontacts.admin" "roles/firebasecrash.symbolMappingsAdmin"
 "roles/identityplatform.admin" "roles/identitytoolkit.admin" "roles/remotebuildexecution.artifactAdmin" "roles/remotebuildexecution.configurationAdmin"
 "roles/remotebuildexecution.reservationAdmin" "roles/runtimeconfig.admin" "roles/vmwareengine.vmwareengineAdmin" "roles/netappcloudvolumes.admin"
 "roles/redisenterprisecloud.admin" "roles/privateca.admin" "roles/privateca.caManager" "roles/privateca.certificateManager" "roles/proximitybeacon.attachmentEditor"
 "roles/pubsub.admin" "roles/pubsublite.admin" "roles/recaptchaenterprise.admin" "roles/automlrecommendations.admin" "roles/recommender.billingAccountCudAdmin"
 "roles/recommender.computeAdmin" "roles/recommender.firewallAdmin" "roles/recommender.iamAdmin" "roles/recommender.projectCudAdmin" "roles/redis.admin" "roles/resourcemanager.folderAdmin"
 "roles/resourcemanager.folderIamAdmin" "roles/resourcemanager.organizationAdmin" "roles/resourcemanager.projectIamAdmin" "roles/run.admin"
 "roles/secretmanager.admin" "roles/securitycenter.admin" "roles/serviceconsumermanagement.tenancyUnitsAdmin" "roles/servicedirectory.admin"
 "roles/servicemanagement.admin" "roles/servicemanagement.quotaAdmin" "roles/servicenetworking.networksAdmin" "roles/serviceusage.apiKeysAdmin"
 "roles/serviceusage.serviceUsageAdmin" "roles/source.admin" "roles/spanner.admin" "roles/spanner.backupAdmin" "roles/spanner.databaseAdmin"
 "roles/spanner.restoreAdmin" "roles/storage.admin" "roles/storage.hmacKeyAdmin" "roles/storage.objectAdmin" "roles/storagetransfer.admin"
 "roles/storage.legacyBucketOwner" "roles/storage.legacyObjectOwner" "roles/cloudsupport.admin" "roles/tpu.admin" "roles/transcoder.admin"
 "roles/vpcaccess.admin")


 for i in ${!ROLES[@]};
 do
   ROLE=${ROLES[$i]}

   FILTER=".bindings[] | select (.role==\"${ROLE}\") | .members[] | select (. | startswith(\"user:\")) | ltrimstr(\"user:\")"
   command=$(gcloud projects get-iam-policy ${PROJECT} --format=json | jq "${FILTER}")
   echo $command
   mapfile -t tot< <(echo $command | wc -w)
   echo "설정된 사용자 수 : "$tot

 if  [[ $tot == 1 ]]; then
   check="[양호]"
   text=${ROLE}
   echo $title1,$title2,$text,$check
   echo -n -e "\033[34m[양호]\033[0m"
   tot=$(( $(( ${tot}+1 )) ))
   suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
   echo $title, $title2, $check
   echo

 elif [[ $tot -gt 1 ]]; then
   check="[취약]"
   resource=${ROLE}
   text="관리자 권한이 1명 이상"
   tot=$(( $(( ${tot}+1 )) ))
   fail_cnt=$(( ${fail_cnt}+1 ))
   export title1
   export title2
   export check
   export resource
   export text
   export tot
   export fail_cnt
   echo $title, $title2, $check, $text, $resource
   echo -n -e "\033[33m[취약]\033[0m"
   sh err_chk.sh

 elif  [[ $tot == 0 ]]; then
   check="[정보]"
   text=${ROLE}
   echo $title1,$title2,$text,$check
   tot=$(( $(( ${tot}+1 )) ))
   echo
 fi
 done
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

  title1="GCP-SVC-AQ03"
  title2="로깅 모니터링(Stack Driver)"

  local title1=$1
  local title2=$2
  local check=$3
  local resource=$4
  local text=$5
  local tot_cnt=$6
  local suc_cnt=$7
  local fail_cnt=$8

  for command in $(gcloud services list --format="value(NAME)" 2>/dev/null)
  do
      readarray resultArray<<< "$command"
      NAME="${resultArray[0]}"
      NAME="${NAME//\"}"
      NAME="${NAME//[$'\t\r\n ']}"
      echo $NAME;
      check="[서비스 체크]"

      if [[ -v apis["$NAME"] ]]; then
          echo ${apis["$NAME"]}
          check="[양호]"
          echo -n -e "\033[34m[양호]\033[0m"
          tot_cnt=$(( $(( ${tot_cnt}+1 )) ))
          suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
          echo "전체 검사수 : "$tot_cnt
          echo "성공 검사수 : "$suc_cnt

      elif [[ ! -v apis["$NAME"] ]]; then
          echo ${apis[$NAME]}
          check="[취약]"
          resource=$NAME
          echo -n -e "\033[33m[취약]\033[0m"
          tot=$(( $(( ${tot}+1 )) ))
          fail_cnt=$(( $(( ${fail_cnt}+1 )) ))
          export title1
          export title2
          export check
          export resource
          export text
          export tot
          export fail_cnt
          echo $title, $title2, $check, $text
          echo "전체 검사수 : "$tot_cnt
          echo "실패 검사수 : "$fail_cnt
          sh err_chk.sh
      fi
  done

}

function AQ05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-AQ05"
title2="KMS 키관리"

command=$(jq '.[].asset.resourceProperties.encryption|select(.)|fromjson|.defaultKmsKeyName|select(.)' {$filename})

echo $command

if [[ $command != {} ]];
then
    check="[양호]"
    resource=$(jq '.[].asset.resourceProperties.encryption|select(.)|fromjson|.defaultKmsKeyName|select(.)' {$filename})
    text="-"
    echo "리소스 : "$resource
    echo $title1,$title2,$check,$resource,$text
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check, $resource, $text
    echo


elif [[ -z $command ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}

function AW05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(jq '.[].asset.iamPolicy.policyBlob |select(.) |fromjson |.bindings[] | select(.role=="roles/deploymentmanager.typeEditor")' {$filename})
title1="GCP-SVC-AW05"
title2="사용자 및 API 액세스 제어"

echo $command

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        echo $title1,$title2
        echo "리소스: "$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo
    elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AX01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(gcloud config get-value proxy/port)
title1="GCP-SVC-AX01"
title2="방화벽 사용"

if [[ -n $command && $command!="unset" ]]; then
    check="[양호]"
    resource=$command
    text="-"
    echo "리소스 : "$command
    echo $title1,$title2,$check,$resource,$text
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo

elif [[ -z $command ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}

function AZ06(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-AZ06"
title2="볼륨 암호화"
command=$(jq '.[].asset.resourceProperties.encryption|select(.)|fromjson|.defaultKmsKeyName|select(.)' {$filename})

echo $command

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        echo $title1,$title2
        echo "리소스: "$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo
    elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function AZ07(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-AZ07"
title2="OS 로그인"

ROLES=("roles/owner" "roles/compute.osLogin" "roles/compute.osAdminLogin" "roles/admin" "roles/owner" "roles/compute.instanceAdmin")
PROJECT=$(gcloud config get-value project)

for i in ${!ROLES[@]};
do
  ROLE=${ROLES[$i]}
  FILTER=".bindings[] | select (.role==\"${ROLE}\") | .members[] | select (. | startswith(\"user:\")) | ltrimstr(\"user:\")"
  command=$(gcloud projects get-iam-policy ${PROJECT} --format=json | jq "${FILTER}")
  mapfile -t tot< <(echo $command | wc -w)
  let tot_cnt+=$tot
done

  if  [[ $tot_cnt > 0 ]]; then
    check="[양호]"
    echo $title1,$title2,$check
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check
    echo

  elif [[ -z $command || $command -eq 0 ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
    fi
}

function AZ09(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-AZ09"
title2="디스크 스냅샷"
command=$(gcloud compute resource-policies list)


if [[ -n $command ]]; then
    check="[양호]"
    resource=$command
    echo "리소스 : "$command
    echo $title1,$title2,$check,$resource
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo

elif [[ -z $command ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}

function AZ10(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-AZ10"
title2="VM 삭제방지"


  for RETURNS in $(gcloud compute instances list --format="csv[no-heading](name,zone)")
  do
    IFS="," read NAME ZONE <<<"${RETURNS}"
    echo -e "Cluster:    ${NAME}"
    echo -e "Location:   ${ZONE}"


    command2=$(gcloud compute instances describe ${NAME} --zone ${ZONE} --format=json | jq '.deletionProtection')
    for VMCHK in $command2
    do
        if [[ -n $VMCHK  ]]; then
            if [[ $VMCHK =~ true ]]; then
                check="[양호]"
                resource=$NAME
                text="-"
                echo $title1,$title2
                echo "리소스: "$NAME
                echo -n -e "\033[34m[양호]\033[0m"
                tot=$(( $(( ${tot}+1 )) ))
                suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
                echo

            elif [[ ! $VMCHK =~ true ]]; then
                check="[취약]"
                resource="-"
                text="리소스 없음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh
            fi
        fi

    done

        if [[ -z $RETURNS ]]; then
                check="[정보]"
                resource="-"
                text="인스턴스 없음"
                tot=$(( $(( ${tot}+1 )) ))
                echo $check, $resource, $text
        fi
done
}


function AZ11(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-AZ11"
title2="보안 부팅"
command=$(jq '.[].asset.resourceProperties.shieldedInstanceConfig | select(.!= null) | fromjson |.enableSecureBoot' {$filename})

  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"
    echo -e "TFCHK:    ${TFCHK}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ true ]]; then
            check="[양호]"
            resource=$command
            text="-"
            echo $title1,$title2
            echo "리소스: - "
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ ! $TFCHK =~ true ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
    fi
done
}


function AZ12(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-AZ12"
title2="vTPM 사용"
command=$(jq '.[].asset.resourceProperties.shieldedInstanceConfig | select(.!= null) | fromjson |.enableVtpm' {$filename})

  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"
    echo -e "TFCHK:    ${TFCHK}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ true ]]; then
            check="[양호]"
            resource=$command
            text="-"
            echo $title1,$title2
            echo "리소스: - "
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ ! $TFCHK =~ true ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
    fi
done
}


function AZ13(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-AZ13"
title2="무결성 모니터링"
command=$(jq '.[].asset.resourceProperties.shieldedInstanceConfig | select(.!= null) | fromjson |.enableIntegrityMonitoring' {$filename})

  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"
    echo -e "TFCHK:    ${TFCHK}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ true ]]; then
            check="[양호]"
            resource=$command
            text="-"
            echo $title1,$title2
            echo "리소스: - "
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ ! $TFCHK =~ true ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
    fi
done
}



function BC05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-BC05"
title2="서비스별 ID 사용"
command=$(jq '.[].asset.iamPolicy.policyBlob |select(.)|fromjson|.bindings[] |select(.role=="roles/run.serviceAgent")' {$filename})

echo $command

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        echo $title1,$title2
        echo "리소스: "$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo
elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function BD07(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(jq '.[].asset.iamPolicy.policyBlob|select(.)|fromjson.auditConfigs |select(.) |.[] |select(.service=="cloudfunctions.googleapis.com")' {$filename})
title1="GCP-SVC-BD07"
title2="데이터 엑세스 감사로그"

echo $command

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        echo $title1,$title2
        echo "리소스: "$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo
    elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}

function BE06(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-BE06"
title2="App Engine 방화벽"
command=$(gcloud app firewall-rules list --format="value(PRIORITY,ACTION)" 2>/dev/null)

for appfirewall in $command
do
  echo -e "앱엔진 방화벽:    ${appfirewall}"
done


if [[ -n $command ]]; then
        check="[양호]"
        echo $title1,$title2,$check
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo

    elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function BG06(){

for CLUSTERZONES in $(gcloud beta container clusters list --format="csv[no-heading](name,zone,MASTER_VERSION)")
do
# Parse (name,zone) --> $CLUSTER, $LOCATION
IFS="," read CLUSTER REGION MASTER_VERSION <<<"${CLUSTERZONES}"
echo -e "Cluster:    ${CLUSTER}"
echo -e "REGION:   ${REGION}"
echo -e "MASTER_VERSION:   ${MASTER_VERSION}"

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

title1="GCP-SVC-BG06"
title2="Kubernetes 버전 최신 상태 유지"

echo $i
for a in ${#i[@]};
do
    NUMBER=$(echo $i[@] | sed 's/[^0-9]*//g')
    NUMBER=${NUMBER:0:5}
    echo "넘버 : "$NUMBER
        for master in ${#MASTER_VERSION[@]};
        do
            MASTER=$(echo $MASTER_VERSION[@] | sed 's/[^0-9]*//g')
            MASTER=${MASTER:0:5}
            echo "마스터 : "$MASTER
            if [[ $MASTER -ge $NUMBER ]];then
              check="[양호]"
              echo $title1,$title2,$check
              echo -n -e "\033[34m[양호]\033[0m"
              tot=$(( $(( ${tot}+1 )) ))
              suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
              echo
            else
               check="[취약]"
               resource="-"
               text="리소스 없음"
               tot=$(( $(( ${tot}+1 )) ))
               fail_cnt=$(( ${fail_cnt}+1 ))
               export title1
               export title2
               export check
               export resource
               export text
               export tot
               export fail_cnt
               echo -n -e "\033[33m[취약]\033[0m"
               sh err_chk.sh
            fi
        done
    done
done
}


function BG07(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-BG07"
title2="마스터 승인 네트워크"


  for RETURNS in $(gcloud beta container clusters list --format="csv[no-heading](name,zone)")
  do
    IFS="," read NAME ZONE <<<"${RETURNS}"
    echo -e "Cluster:    ${NAME}"
    echo -e "Location:   ${ZONE}"


    command2=$(gcloud container clusters describe ${NAME} --zone ${ZONE} --format=json | jq '.masterAuthorizedNetworksConfig.enabled')
    for MSCHK in $command2
    do
        if [[ -n $MSCHK && $MSCHK != "null" ]]; then
            check="[양호]"
            resource=$NAME
            text="-"
            echo $title1,$title2
            echo "리소스: "$NAME
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ -z $MSCHK || $MSCHK == "null" ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi

    done

        if [[ -z $RETURNS ]]; then
                check="[정보]"
                resource="-"
                text="인스턴스 없음"
                tot=$(( $(( ${tot}+1 )) ))
                echo $check, $resource, $text
        fi
done
}


function BG08(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-BG08"
title2="PodSecurityPolicy"
command=$(jq '.[].asset.resourceProperties.metadata|select(.)|fromjson.annotations.EnablePodSecurityPolicy|select(.)' {$filename})


  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"
    echo -e "TFCHK:    ${TFCHK}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ true ]]; then
            check="[양호]"
            resource=$command
            text="-"
            echo $title1,$title2
            echo "리소스: - "
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ ! $TFCHK =~ true ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
    fi
done
}

function BG10(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(jq '.[].asset.resourceProperties.nodePools|select(.)|fromjson|.[]|.config|.metadata | ."disable-legacy-endpoints"' {$filename})
title1="GCP-SVC-BG10"
title2="클러스터 메타데이터 보호"

  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"
    echo -e "TFCHK:    ${TFCHK}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ true ]]; then
            check="[양호]"
            resource=$command
            text="-"
            echo $title1,$title2
            echo "리소스: - "
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ ! $TFCHK =~ true ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi
    fi

    if [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh

    fi
done
}

function BG11(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SEC-BG11"
title2="GKE 보안 노드"

command=$(gcloud container clusters list --format="value(NAME,LOCATION)")

  for CLUSTERZONES in $(gcloud beta container clusters list --format="csv[no-heading](name,zone)")
  do
    IFS="," read CLUSTER LOCATION <<<"${CLUSTERZONES}"
    echo -e "Cluster:    ${CLUSTER}"
    echo -e "Location:   ${LOCATION}"


    command2=$(gcloud container clusters describe ${CLUSTER} --zone ${LOCATION} --format=json | jq '.shieldedNodes.enabled')
    for masterCheck in $command2
    do
            echo "$command2"

            if [[ -z "$command2" ]]; then
                check="[취약]"
                resource="-"
                text="마스터 승인 네트워크 관리하지 않음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh


            elif [[ "$command2"==null ]]; then
                check="[취약]"
                resource="-"
                text=$resource
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh

            elif [[ "$command2"==true ]]; then
                check="[양호]"
                resource=$command2
                text="-"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[34m[양호]\033[0m"
                sh err_chk.sh

            fi
    done
done
}


function BH06()
{
local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-BH06"
title2="인증 방식"

if [[ -f /$HOME/.docker/config.json ]]; then
     check="[양호]"
     text="-"
     echo $title1,$title2,$check
     echo -n -e "\033[34m[양호]\033[0m"
     tot=$(( $(( ${tot}+1 )) ))
     #suc_cnt=$(( ${suc_cnt}+1 ))
     echo "인증 방식이 설정되어 있습니다."
     echo

else echo -n -e "\033[31m[취약]\033[0m"
     check="[취약]"
     text="리소스 없음"
     tot=$(( $(( ${tot}+1 )) ))
     fail_cnt=$(( ${fail_cnt}+1 ))
     echo
     export title1
     export title2
     export check
     export resource
     export text
     export tot
     export fail_cnt
     echo -n -e "\033[33m[취약]\033[0m"
     sh err_chk.sh
fi
}

function BH07(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(jq '.[].asset.resourceProperties.iamConfiguration|select(.)|fromjson |.uniformBucketLevelAccess' {$filename})
title1="GCP-SVC-BH07"
title2="액세스 제어 구성"

echo $command

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        echo $title1,$title2
        echo "리소스: "$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo
    elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


function BH08(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-BH08"
title2="Docker Hub 미러 보호"
command=$(docker system info | grep -A 1 'Registry Mirrors' 2>/dev/null)

if [[ -n $command ]]; then
    check="[양호]"
    resource=$command
    echo $title1,$title2,$check,$resource
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check
    echo

elif [[ -z $command ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}


function BU05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-BU05"
title2="서명된 URL 키 구성"
command=$(jq '.[].asset.resourceProperties.cdnPolicy|select(.)|fromjson|.signedUrlKeyNames[]' {$filename} 2>/dev/null)

if [[ -n $command ]]; then
    check="[양호]"
    resource=$command
    echo $title1,$title2,$check,$resource
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check
    echo

elif [[ -z $command ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}


function BV05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(jq '.[].asset.resourceProperties.dnssecConfig |select(.) |fromjson|.state' {$filename})
title1="GCP-SVC-BV05"
title2="DNSSEC 설정"

for i in $command
do
    echo $i

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        echo $title1,$title2
        echo "리소스: "$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo
    elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
    fi
done
}


function BY05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-BY05"
title2="SSL 정책 사용"

command=$(gcloud compute ssl-certificates list --format="value(NAME)")
command2=$(gcloud compute url-maps list)

for i in $command
do

if [[ -n $command ]];
then
    check="[양호]"
    resource=$command
    text="-"
    echo "리소스 : "$resource
    echo $title1,$title2,$check,$resource,$text
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check, $resource, $text
    echo


elif [[ -z $command ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
done

if [[ -z $command2 ]]; then
    check="[정보]"
    resource="-"
    text="로드밸런서 없음"
    tot=$(( $(( ${tot}+1 )) ))
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
fi
}


function BZ05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-BZ05"
title2="NAT 연결 제한 시간"

command=$(gcloud compute routers list --format="csv[no-heading](NAME,REGION)")

  for ROUTERS in $command
  do
    # Parse (name,zone) --> $CLUSTER, $LOCATION
    IFS="," read router region <<<"${ROUTERS}"
    echo -e "router: ${router}"
    echo -e "region: ${region}"

    command2=$(gcloud compute routers nats list --router ${router} --region ${region} --format="value(NAME)")
    for NATS in $command2
    do
        IFS="," read nat <<<"${command2}"
        echo -e "nat: ${nat}"

        command3=$(gcloud compute routers nats describe ${nat} --router ${router} --region ${region} | grep 'icmpIdleTimeoutSec')
        for TOS in $command3
        do
            IFS="," read TOS <<<"${command3}"
            echo "TimeoutSec : $TOS"

            if [[ -z $TOS ]]; then
                check="[취약]"
                resource="-"
                text="NAT 연결 제한 시간 없음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh

            elif [[ -n $TOS ]]; then
                check="[양호]"
                resource=$command2
                tot=$(( $(( ${tot}+1 )) ))
                suc_cnt=$(( ${suc_cnt}+1 ))
                echo $title, $title2, $check
                echo -n -e "\033[34m[양호]\033[0m"
            fi
        done
        if [[ -z $NATS ]]; then
            check="[정보]"
            resource="-"
            text="NAT Gateway 없음"
            tot=$(( $(( ${tot}+1 )) ))
            echo $title, $title2, $check, $text
        fi
    done
    if [[ -z $ROUTERS ]]; then
        check="[정보]"
        resource="-"
        text="ROUTER 없음"
        tot=$(( $(( ${tot}+1 )) ))
        echo $title, $title2, $check, $text
    fi
done
}


function CA05(){

local name=$1
local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
echo $name

url=$(gcloud compute url-maps list --format="csv[no-heading](NAME, DEFAULT_SERVICE)")
title1="GCP-SVC-CA05"
title2="고급 보안 관리 구성"

if [[ -n $url ]]; then
    check="[양호]"
    resource=$url
    text="-"
    echo "리소스 : "$resource
    echo $title1,$title2,$check,$resource,$text
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check, $resource, $text
    echo

elif [[ -z $url ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}


function CB06(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-CB06"
title2="객체 수명 주기 관리"

command=$(gsutil list)

  for BUCKETLIST in $command
  do
    read -r bucketname <<<"${BUCKETLIST}"
          if [[ -z $bucketname ]]; then
              check="[리소스 없음]"
              resource="-"
              text="리소스 없음"
              tot=$(( $(( ${tot}+1 )) ))
              fail_cnt=$(( ${fail_cnt}+1 ))
              export title1
              export title2
              export check
              export resource
              export text
              export tot
              export fail_cnt
              echo -n -e "\033[33m[취약]\033[0m"
              sh err_chk.sh
            fi

    command2=$(gsutil versioning get ${bucketname})
    for version in $command2
    do
        echo $version
        if [[ $version == Suspended ]]; then
                check="[취약]"
                resource="-"
                text="버전 없음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh
        elif [[ $version == Enabled ]]; then
                check="[양호]"
                resource=$command
                text="-"
                echo "리소스 : "$resource
                echo -n -e "\033[34m[양호]\033[0m"
                tot=$(( $(( ${tot}+1 )) ))
                suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
                echo $title, $title2, $check, $resource, $text
                echo
            fi
    done
done
}


function CB07(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-CB07"
title2="객체 버전 관리 사용"

command=$(gsutil list)

  for BUCKETLIST in $command
  do
    read -r bucketname <<<"${BUCKETLIST}"
    echo -e "버킷명 :    ${bucketname}"
          if [[ -z $bucketname ]]; then
              check="[리소스 없음]"
              resource="-"
              text="리소스 없음"
              tot=$(( $(( ${tot}+1 )) ))
              fail_cnt=$(( ${fail_cnt}+1 ))
              export title1
              export title2
              export check
              export resource
              export text
              export tot
              export fail_cnt
              echo $title, $title2, $check, $text
              echo -n -e "\033[33m[취약]\033[0m"
              sh err_chk.sh
        fi

    command2=$(gsutil versioning get ${bucketname})
    for version in $command2
    do
        echo $version
        if [[ $version == Suspended ]]; then
                check="[취약]"
                resource="-"
                text="버전 없음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh
        elif [[ $version == Enabled ]]; then
                check="[양호]"
                resource=$command
                text="-"
                echo "리소스 : "$resource
                echo -n -e "\033[34m[양호]\033[0m"
                tot=$(( $(( ${tot}+1 )) ))
                suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
                echo $title, $title2, $check, $resource, $text
                echo
        fi
    done
done
}


function CB09(){

local name=$1
local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
echo $name

HMAC=$(gsutil hmac list)
title1="GCP-SEC-AF02"
title2="웹 어플리케이션 공격 대응 설정"

if [[ -n $HMAC ]]; then
    check="[양호]"
    resource=$command
    text="-"
    echo "리소스 : "$HMAC
    echo $title1,$title2,$check,$resource,$text
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check, $resource, $text
    echo

elif [[ -z $HMAC ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}


function CD05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-CD05"
title2="NFS 파일 잠금"
command=$(gcloud compute firewall-rules list | grep '111\|2046\|4045')


if [[ -n $command ]]; then
    check="[양호]"
    resource=$command
    text="-"
    echo "리소스 : "$resource
    echo $title1,$title2,$check,$resource
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check, $resource, $text
    echo

elif [[ -z $command ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}


function CF06(){

local name=$1
local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
echo $name

title1="GCP-SVC-CF06"
title2="연결 조직 정책 구성"

command=$(gcloud sql instances list --format="value(NAME)")
  for BUCKETS in $command
  do
    read -r bucketname <<<"${BUCKETS}"
    echo -e "버킷명 :    ${bucketname}"


        if [[ -z $bucketname  ]]; then
                check="[리소스 없음]"
                resource="-"
                text="리소스 없음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh
        fi

    command2=$(gcloud sql instances describe ${bucketname} | grep -P "authorizedNetwork")
    for network in $command2
    do
        if [[ -n $network ]]; then
                check="[양호]"
                resource=$command2
                text="-"
                echo "리소스 : "$resource
                echo -n -e "\033[34m[양호]\033[0m"
                tot=$(( $(( ${tot}+1 )) ))
                suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
                echo $title, $title2, $check, $resource, $text
                echo
        fi
    done
            if [[ -z $network ]]; then
                check="[취약]"
                resource="-"
                text="연결 조직 정책 구성 없음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh
            fi

done
}


function CF07(){

local name=$1
local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
echo $name

title1="GCP-SVC-CF07"
title2="SSL/TLS 인증서 구성"

command=$(gcloud sql instances list --format="value(NAME)")
  for BUCKETS in $command
  do
    read -r instancename <<<"${BUCKETS}"
    echo -e "버킷명 :    ${instancename}"


        if [[ -z $instancename  ]]; then
                check="[리소스 없음]"
                resource="-"
                text="리소스 없음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
        fi

    command2=$(gcloud beta sql ssl server-ca-certs list --instance ${instancename} --format="value(SHA1_FINGERPRINT)")
    for ssl in $command2
    do
        if [[ -n $ssl ]]; then
                check="[양호]"
                resource="${command2:20}"
                text="-"
                echo -n -e "\033[34m[양호]\033[0m"
                tot=$(( $(( ${tot}+1 )) ))
                suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
                echo $title, $title2, $check, $resource, $text
                echo

        elif [[ -z $ssl ]]; then
            check="[취약]"
            resource="-"
            text="연결 조직 정책 구성 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo $title, $title2, $check, $text
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi
    done
done
}


function CF08(){

local name=$1
local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-CF08"
title2="인스턴스 고가용성 설정"

command=$(gcloud sql instances list --format="value(NAME)")
  for INSTANCE in $command
  do
    read -r name <<<"${INSTANCE}"
    echo -e "버킷명 :    ${name}"

      if [[ -z $name  ]]; then
          check="[정보]"
          resource="-"
          text="sql 인스턴스 없음"
          tot=$(( $(( ${tot}+1 )) ))
          echo $title, $title2, $check, $text
          echo -n -e "\033[33m[취약]\033[0m"
      fi

    command2=$(gcloud beta sql instances describe ${name} --format=json | jq '.settings.availabilityType')
    for availability in $command2
    do
      if [[ -z $availability ]]; then
              check="[취약]"
              resource="-"
              text="고가용성 설정 없음"
              tot=$(( $(( ${tot}+1 )) ))
              fail_cnt=$(( ${fail_cnt}+1 ))
              export title1
              export title2
              export check
              export resource
              export text
              export tot
              export fail_cnt
              echo $title, $title2, $check, $text
              echo -n -e "\033[33m[취약]\033[0m"
              sh err_chk.sh
      fi
    done
    if [[ -n $availability ]]; then
        check="[양호]"
        resource=$command2
        echo "리소스 : "$resource
        # # echo $title1,$title2,$check,$resource,$text
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo $title, $title2, $check, $resource
        echo
    fi
done
}


function CF09(){

local name=$1
local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-CF09"
title2="백업 및 관리"

command=$(gcloud sql instances list --format="value(NAME)")
  for INSTANCE in $command
  do
    read -r name <<<"${INSTANCE}"
    echo -e "버킷명 :    ${name}"


        if [[ -z $name  ]]; then
                check="[정보]"
                resource="-"
                text="sql 인스턴스 없음"
                tot=$(( $(( ${tot}+1 )) ))
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
        fi

    command2=$(gcloud beta sql instances describe ${name} --format=json | jq '.settings.backupConfiguration')
    for backup in $command2
    do
        if [[ -z $backup ]]; then
                check="[취약]"
                resource="-"
                text="고가용성 설정 없음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh
        fi
    done
            if [[ -n $backup ]]; then
                check="[양호]"
                resource=$backup
                echo "리소스 : "$resource
                # # echo $title1,$title2,$check,$resource,$text
                echo -n -e "\033[34m[양호]\033[0m"
                tot=$(( $(( ${tot}+1 )) ))
                suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
                echo $title, $title2, $check, $resource
                echo
            fi
done
}


function CI06(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-CI06"
title2="장애 조치 관리"

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
            echo $title1,$title2
            echo "리소스: "$NAME
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ -z $APCHK ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh

        fi

    done

        if [[ -z $RETURNS ]]; then
                check="[정보]"
                resource="-"
                text="인스턴스 없음"
                tot=$(( $(( ${tot}+1 )) ))
                echo $check, $resource, $text
        fi
done
}


function CL05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-CL05"
title2="Redis 버전 업그레이드"

command=$(gcloud redis regions list --format="value(NAME)")

  for regions in $command
  do
    command2=$(gcloud redis instances list --region ${regions} --format=json | jq '.[].redisVersion')
    for versionCheck in $command2
    do
			echo $command2
            if [[ $versionCheck =~ "REDIS_5_0" ]]; then
                check="[양호]"
                resource=$versionCheck
                echo $title1,$title2,$check,$resource
                echo -n -e "\033[34m[양호]\033[0m"
                tot=$(( $(( ${tot}+1 )) ))
                suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
                echo

            elif [[ $versionCheck == "REDIS_4_0" ]]; then
                check="[취약]"
                resource="-"
                text="Redis 버전이 구버전임"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh

            fi
    done
done

            if [[ -z $command  ]]; then
                check="[취약]"
                resource="-"
                text="리소스 없음"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh
              fi
}



function CP06(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


command=$(gcloud compute networks subnets list --format="get(privateIpGoogleAccess)")
title1="GCP-SVC-CP06"
title2="비공개 인스턴스"

  for RETURNS in $command
  do
    read TFCHK <<<"${RETURNS}"
    echo -e "TFCHK:    ${TFCHK}"

    if [[ -n $TFCHK  ]]; then
        if [[ $TFCHK =~ True ]]; then
            check="[양호]"
            resource=$command
            text="-"
            echo $title1,$title2
            echo "리소스: - "
            echo -n -e "\033[34m[양호]\033[0m"
            tot=$(( $(( ${tot}+1 )) ))
            suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
            echo

        elif [[ $TFCHK =~ False ]]; then
            check="[취약]"
            resource="-"
            text="리소스 없음"
            tot=$(( $(( ${tot}+1 )) ))
            fail_cnt=$(( ${fail_cnt}+1 ))
            export title1
            export title2
            export check
            export resource
            export text
            export tot
            export fail_cnt
            echo -n -e "\033[33m[취약]\033[0m"
            sh err_chk.sh
        fi

    elif [[ -z $TFCHK ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
    fi
done
}


function CR06(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-CR06"
title2="클러스터 관리"

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
                echo "리소스 : "$name
                echo $title1,$title2,$check,$resource,$text
                echo -n -e "\033[34m[양호]\033[0m"
                tot=$(( $(( ${tot}+1 )) ))
                suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
                echo $title, $title2, $check, $resource, $text
                echo

            elif [[ -n $procchk ]]; then
                check="[취약]"
                resource="-"
                text="Dataproc 클러스터 사용 중"
                tot=$(( $(( ${tot}+1 )) ))
                fail_cnt=$(( ${fail_cnt}+1 ))
                export title1
                export title2
                export check
                export resource
                export text
                export tot
                export fail_cnt
                echo $title, $title2, $check, $text
                echo -n -e "\033[33m[취약]\033[0m"
                sh err_chk.sh
            fi
    done
done
}


function CU05(){

local name=$1
local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
echo $name

pipelines=$(gcloud beta lifesciences operations list --format="value(ID)")
title1="GCP-SVC-CU05"
title2="장기 실행 작업 관리"

if [[ -n $pipelines ]]; then
    check="[양호]"
    resource=$pipelines
    echo "리소스 : "$resource
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title1,$title2,$check,$resource
    echo

elif [[ -z $pipelines ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}

function DE05() {
local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-DE05"
title2="고객 관리 암호화 키 사용"

cmd=$(jq '.[].asset.resourceProperties.encryption|select(.)|fromjson|.defaultKmsKeyName|select(.)' {$filename})

if [[ -n $cmd ]]; then
    check="[양호]"
    resource=$cmd
    text="-"
    echo "리소스 : "$cmd
    echo $title1,$title2,$check,$resource,$text
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check, $resource, $text
    echo
elif [[ -z $cmd ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    sh err_chk.sh
fi
}


function DE06(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

title1="GCP-SVC-DE06"
title2="학습시 VPC 서비스 제어 사용"
command=$(gcloud access-context-manager perimeters list)

if [[ -n $command ]]; then
    check="[양호]"
    resource=$($command)
    text="-"
    echo "리소스 : "$resource
    echo $title1,$title2,$check,$resource,$text
    echo -n -e "\033[34m[양호]\033[0m"
    tot=$(( $(( ${tot}+1 )) ))
    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
    echo $title, $title2, $check, $resource, $text
    echo

elif [[ -z $command ]]; then
    check="[취약]"
    resource="-"
    text="리소스 없음"
    tot=$(( $(( ${tot}+1 )) ))
    fail_cnt=$(( ${fail_cnt}+1 ))
    export title1
    export title2
    export check
    export resource
    export text
    export tot
    export fail_cnt
    echo $title, $title2, $check, $text
    echo -n -e "\033[33m[취약]\033[0m"
    sh err_chk.sh
fi
}


function DM05(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5


title1="GCP-SVC-DM05"
title2="기기 사용자 인증 정보 확인"

  regions=(asia-east1 europe-west1 us-central1)

  for (( i = 0; i < ${#regions[@]}; i++ ))
  do
          for RETURNS in $(gcloud iot registries list --region ${regions[$i]} --format="value(ID)")
		  do
			read -r -a NAME <<<"${RETURNS}"
          	echo -e "이름 :"    ${NAME}
            echo "리전 : " ${regions[$i]}

                command2=$(gcloud iot registries describe ${NAME} --region ${regions[$i]} --format=json | jq '.credentials[].publicKeyCertificate.certificate')
                if [[ -n $command2 ]]; then
                    check="[양호]"
                    resource=$NAME
                    text="-"
                    echo $title1,$title2
                    echo "리소스: "$NAME
                    echo -n -e "\033[34m[양호]\033[0m"
                    tot=$(( $(( ${tot}+1 )) ))
                    suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
                    echo

                elif [[ -z $command2 ]]; then
                    check="[취약]"
                    resource="-"
                    text="리소스 없음"
                    tot=$(( $(( ${tot}+1 )) ))
                    fail_cnt=$(( ${fail_cnt}+1 ))
                    export title1
                    export title2
                    export check
                    export resource
                    export text
                    export tot
                    export fail_cnt
                    echo -n -e "\033[33m[취약]\033[0m"
                    sh err_chk.sh
                fi

	          done

                if [[ -z $RETURNS ]]; then
                    check="[정보]"
                    resource="-"
                    text="레지스트리 리소스 없음"
                    tot=$(( $(( ${tot}+1 )) ))
                    fail_cnt=$(( ${fail_cnt}+1 ))
                    export title1
                    export title2
                    export check
                    export resource
                    export text
                    export tot
                    echo -n -e "\033[33m[취약]\033[0m"
    	        fi
		  done
}

function DN06(){


local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5

command=$(jq '.[].asset.iamPolicy.policyBlob |select(.) |fromjson |.bindings[] | select(.role=="roles/container.developer")|.members[]' {$filename})
title1="GCP-SVC-DN06"
title2="서비스 계정 권한 액세스"

if [[ -n $command  ]]; then
        check="[양호]"
        resource=$command
        text="-"
        echo $title1,$title2
        echo "리소스: "$command
        echo -n -e "\033[34m[양호]\033[0m"
        tot=$(( $(( ${tot}+1 )) ))
        suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
        echo
    elif [[ -z $command ]]; then
        check="[취약]"
        resource="-"
        text="리소스 없음"
        tot=$(( $(( ${tot}+1 )) ))
        fail_cnt=$(( ${fail_cnt}+1 ))
        export title1
        export title2
        export check
        export resource
        export text
        export tot
        export fail_cnt
        echo -n -e "\033[33m[취약]\033[0m"
        sh err_chk.sh
fi
}


cmds=('AA01' 'AA02' 'AA03' 'AA04' 'AA05' 'AA06' 'AB02' 'AD01' 'AD02' 'AD04' 'AD05' 'AE01' 'AE02' 'AE03' 'AE04' 'AE05' 'AE06' 'AE07' 'AF01' 'AG01'
'AH01' 'AI01' 'AJ02' 'AK01' 'AM02' 'AP01' 'AQ01' 'AQ03' 'AQ05' 'AW05' 'AX01' 'AZ06' 'AZ07' 'AZ09' 'AZ10' 'AZ11' 'AZ12' 'AZ13' 'BC05' 'BD07' 'BE06'
'BG06' 'BG07' 'BG08' 'BG10' 'BG11' 'BH06' 'BH07' 'BH08' 'BU05' 'BV05' 'BY05' 'BZ05' 'CA05' 'CB06' 'CB07' 'CB09' 'CD05' 'CF06' 'CF07' 'CF08' 'CF09'
'CI06' 'CL05' 'CP06' 'CR06' 'CT05' 'CU05' 'DE05' 'DE06' 'DM05' 'DN06')
for cmd in "${cmds[@]}"; do
    $cmd
done
