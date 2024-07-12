# Creating Tasks that use gMSA for runas user cannot be done with the Task Scheduler GUI
# This script will take as an argument enough information to create a task template
# That can be configured after it is created.
# Initial v.1 takes as arguments *in quotes*


$TaskAction = $args[0]        #quoted path to executable script
$Task_gMSA = $args[1]         #gMSA name without domain\
$TaskDescription = $args[2]   #quoted text of short description of task 
$TaskName = $args[3]          #quoted text Name of task
#$TaskTrigger = $args[4]       #quoted text that adheres to format -Daily, with -At of time of day in 24hr format

$action = New-ScheduledTaskAction $TaskAction
$principal = New-ScheduledTaskPrincipal -UserID MFG\$Task_gMSA -LogonType Password -RunLevel Highest
$trigger = New-ScheduledTaskTrigger -Daily -At 18:00
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RunOnlyIfIdle -StartWhenAvailable

#Register-ScheduledTask $TaskName -Description $TaskDescription -Action $action -Trigger $trigger -Principal $principal -AsJob -RunLevel Highest -Force
#Register-ScheduledTask $TaskName -Description $TaskDescription -Action $action -Trigger $trigger -Principal $principal -AsJob -RunLevel Highest 

# this Register-ScheduledTask command is the one that worked. Those above produced ambiguous parameter cannot be set errors
Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $action -Trigger $trigger -Principal $principal -Settings $settings
