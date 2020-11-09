#!/bin/bash

function AQ01(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
tot_cnt=0

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
   mapfile -t tot_cnt< <(echo $command | wc -w)
   echo $tot_cnt

 if  [[ $tot_cnt == 1 ]]; then
   check="[양호]"
   text=${ROLE}
   echo $title1,$title2,$text,$check
   echo -n -e "\033[34m[양호]\033[0m"
   tot=$(( $(( ${tot}+1 )) ))
   suc_cnt=$(( $(( ${suc_cnt}+1 )) ))
   echo $title, $title2, $check
   echo

 elif [[ $tot_cnt -gt 1 ]]; then
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

 elif  [[ $tot_cnt == 0 ]]; then
   check="[정보]"
   text=${ROLE}
   echo $title1,$title2,$text,$check
   tot=$(( $(( ${tot}+1 )) ))
   echo
 fi
 done
 }



function AZ07(){

local title1=$1
local title2=$2
local check=$3
local resource=$4
local text=$5
tot_cnt=0

title1="GCP-SVC-AZ07"
title2="OS 로그인"

PROJECT=$(gcloud config get-value project)
ROLES=("roles/owner" "roles/compute.osLogin" "roles/compute.osAdminLogin" "roles/admin" "roles/owner" "roles/compute.instanceAdmin")

declare -A cnt
for i in ${!ROLES[@]};
do
  ROLE=${ROLES[$i]}
  FILTER=".bindings[] | select (.role==\"${ROLE}\") | .members[] | select (. | startswith(\"user:\")) | ltrimstr(\"user:\")"
  command=$(gcloud projects get-iam-policy ${PROJECT} --format=json | jq "${FILTER}")
  mapfile -t tot_cnt< <(echo $command | wc -w)
done

if  [[ $tot_cnt > 0 ]]; then
  check="[양호]"
  text="-"
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


 cmds=('AQ01' 'AZ07')
for cmd in "${cmds[@]}"; do
    $cmd
done
