alias ls=ls
CF="GCP_점검결과_$(date +"%H:%M").csv"

function error(){
    echo $title1,$title2,$check,$resource,$text >> $CF 2>&1
}
error

# if [[ -z ${fail_cnt} || ${fail_cnt} -eq 0 ]]; then
#     echo "취약 점검을 마쳤습니다."
#     echo "취약 사항이 없습니다."
# fi


echo "총 점검 갯수 : "$tot
echo "총 취약 갯수 : "$fail_cnt
echo "총 점검 갯수 : "$tot, "총 취약 갯수 : "$fail_cnt >> $CF 2>&1
