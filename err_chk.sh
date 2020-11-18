alias ls=ls
CF="GCP_점검결과_${filename}.csv"

function error(){
    echo $title1,$title2,$check,$resource,$text >> $CF 2>&1
}
error


