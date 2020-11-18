echo -e "\033[36m###############################################\033[0m"
echo -e "\033[36m############# GCP 보안 체크리스트 점검 #############\033[0m"
echo -e "\033[36m###############################################\033[0m"
echo ""
echo ""
echo -e "점검 시작시간:" 
date "+%Y-%m-%d %H:%M:%S KST"
sleep 1
echo -e "\033[36m*********************리소스를 다운받고 있습니다.************************\033[0m"

$(sudo ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime)

filename="result_$(date +"%H:%M").json"
ORG="$(gcloud organizations list --format="value(name)")"
echo "조직명 : " $ORG
gcloud alpha scc assets list $ORG --format=json >> ${filename}
export filename 

#jq 모듈 설치
jq=`which jq`
if [ "X$jq" == "X" ]
then
    `apt-get install -y jq`
fi

sh getter.sh

