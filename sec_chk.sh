echo -e "\033[36m*********************************************************************\033[0m"
echo -e "\033[33m*                    GCP  보안 취약점 진단 스크립트                    *\033[0m"
echo -e "\033[36m**********************************************************************\033[0m"
echo -e "\033[36m*    항목에 따라 시간이 다른 항목에 비하여 다소 오래 걸릴수 있습니다   \033[0m*"
echo -e "\033[36m*                   시간을 KST로 설정합니다.                           \033[0m*"
echo -e "\033[36m**********************************************************************\033[0m"
echo ""
echo ""
echo -e "\033[36m*********************리소스를 다운받고 있습니다.************************\033[0m"


$(sudo ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime)

filename="result_$(date +"%H:%M").json"
#echo "success1" > $filename 2>&1
ORG="$(gcloud organizations list --format="value(name)")"
echo "조직명 : " $ORG
gcloud alpha scc assets list $ORG --format=json >> ${filename}
export filename
sh getter.sh
