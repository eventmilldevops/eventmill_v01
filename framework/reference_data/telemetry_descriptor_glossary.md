# Telemetry and generated detection descriptor glossary

Sources: [telemetry library](../../eventmill_v01/framework/reference_data/telemetry_library.json) version 0.3.0 (36 sources), and [detection output](exports_attack_path_detection_designer_20260923_030349.json) (9 drafts across 2 LLM responses).

Scope: all 38 distinct fields.derived names and all 59 distinct fields.absent_without_enrichment names in this library, plus every normalized-field alias and thresholds entry in the named output, grouped by response and draft. Native fields, source IDs, behavior labels, schema keys, and fixed status codes are not enumerated as library descriptors here. Single-word aliases are included so each draft mapping is complete.

Library meanings below are plain-language interpretations of the names and their source context, not formal calculation specifications. Derived means an indicator to calculate or enrich; it does not prove an implementation exists. Enrichment descriptors identify information the source lacks on its own. All sources report collection status unknown.

LLM terms are observed in this specific output, not predictions of a fixed vocabulary. Future responses may choose other names and values. Both calls record claude-opus-5; engagement.model_attribution describes the upstream projector and must not be used to identify the draft-generation model. All drafts remain draft_unvalidated.

## Library-derived indicators

| Descriptor | Origin / source | Short meaning |
|---|---|---|
| `accounts_holding_both_maker_and_checker_roles` | Library: derived indicator; `identity.role_assignment_export` | Accounts with both transaction-creation and transaction-approval roles. |
| `active_credential_for_leaver` | Library: derived indicator; `badge_audit.monthly_report` | Whether an access credential remains active for someone who has left. |
| `actor_approver_same_person` | Library: derived indicator; `ledger.adjustment_audit` | Whether the adjustment creator and approver resolve to the same person. |
| `adjustments_just_below_threshold` | Library: derived indicator; `ledger.adjustment_audit` | Adjustments clustered just below a review or approval threshold. |
| `allowed_after_rule_match` | Library: derived indicator; `edge.waf_decision` | Whether a request was allowed even though it matched a WAF rule. |
| `antipassback_violation` | Library: derived indicator; `badge.door_event` | Whether badge use violates the expected entry/exit sequence. |
| `beaconing_interval` | Library: derived indicator; `netflow.records` | Time between recurring network connections that may form a periodic communication pattern. |
| `clustered_complaints_same_category_same_week` | Library: derived indicator; `complaints.queue_tickets` | A concentration of complaints in one category during the same week. |
| `cold_start_flag` | Library: derived indicator; `baseline.redemption_velocity` | Whether there is insufficient historical data to establish a reliable baseline. |
| `collection_gap` | Library: derived indicator; `historian.tag_change` | A period in which expected historian observations are missing. |
| `command_outside_shift_pattern` | Library: derived indicator; `hmi.operator_action` | Whether an operator command departs from expected activity for that shift. |
| `deny_streak` | Library: derived indicator; `badge.door_event` | A consecutive sequence of denied physical-access attempts. |
| `dormant_account_touched` | Library: derived indicator; `ledger.adjustment_audit` | Whether an adjustment affects an account considered inactive. |
| `dormant_high_balance_browsing` | Library: derived indicator; `agent_console.session_recording` | Browsing inactive customer accounts that hold relatively large balances. |
| `dormant_port_activation` | Library: derived indicator; `network_device.aaa` | Whether a previously inactive network port became active. |
| `egress_volume_per_principal` | Library: derived indicator; `object_store.access` | Amount of data transferred out by a user or service identity over a defined interval. |
| `exec_into_pod_rate` | Library: derived indicator; `kubernetes.api_audit` | Frequency of remote command-execution sessions into Kubernetes pods. |
| `first_time_principal_topic_pair` | Library: derived indicator; `kafka.authorizer` | Whether this identity has been observed accessing this Kafka topic before. |
| `first_time_route_for_principal` | Library: derived indicator; `application.runtime_log` | Whether an application route is new in the observed history of this user or service identity. |
| `impossible_travel` | Library: derived indicator; `saml_idp.authentication` | Whether successive identity events imply travel that is implausible for the elapsed time. |
| `interactive_logon_outside_shift` | Library: derived indicator; `windows.security_events` | Whether an interactive login occurred outside the person's expected work shift. |
| `lookup_without_an_open_ticket` | Library: derived indicator; `agent_console.session_recording` | Whether an agent accessed customer information without an associated open support ticket. |
| `new_device_on_vlan` | Library: derived indicator; `netflow.records` | Whether a device is newly observed on a particular virtual LAN. |
| `open_duration` | Library: derived indicator; `badge.door_contact_alarm` | How long a door remained open. |
| `out_of_hours_grant` | Library: derived indicator; `badge.door_event` | Whether physical access was granted outside the permitted or expected hours. |
| `read_volume_per_principal_per_hour` | Library: derived indicator; `smb.object_access` | Amount of file-read activity attributed to an identity each hour; the unit needs definition. |
| `redemptions_without_a_matching_ledger_event` | Library: derived indicator; `partner.settlement_file` | Redemptions for which no corresponding ledger event can be found. |
| `rows_touched_estimate` | Library: derived indicator; `pgaudit.object_access` | Approximate number of database rows affected or accessed; the estimation method must be defined. |
| `secret_read_rate_per_principal` | Library: derived indicator; `vault.audit_device` | Number of secret reads by an identity per defined time interval. |
| `service_ticket_burst` | Library: derived indicator; `ad.authentication` | An unusually concentrated set of service-ticket requests over a defined interval. |
| `setpoint_outside_operating_envelope` | Library: derived indicator; `historian.tag_change` | Whether a process setpoint is outside its defined acceptable operating bounds. |
| `source_silent_versus_baseline` | Library: derived indicator; `collector.heartbeat` | Whether a source has stopped producing events relative to its expected activity. |
| `suppression_coinciding_with_an_adjustment` | Library: derived indicator; `email.suppression_record` | Whether notification suppression occurs in association with a ledger adjustment. |
| `token_file_read_by_unexpected_process` | Library: derived indicator; `container.file_access` | Whether a process outside the expected set read a token file. |
| `unregistered_device_present` | Library: derived indicator; `asset_audit.quarterly_report` | Whether an observed physical device has no matching asset-register entry. |
| `variance_outside_normal_band` | Library: derived indicator; `finance.points_liability_reconciliation` | Whether a reconciliation variance falls outside its expected range. |
| `vendor_session_outside_maintenance_window` | Library: derived indicator; `remote_access.session` | Whether a vendor remote-access session occurs outside approved maintenance times. |
| `workflow_changed_and_run_by_same_actor` | Library: derived indicator; `github_actions.workflow_run` | Whether the same account changed a workflow definition and triggered its execution. |

## Library enrichment descriptors

| Descriptor | Origin / source | Short meaning |
|---|---|---|
| `application_outcome` | Library: enrichment gap; `edge.waf_decision` | What happened inside the application after the WAF decision. |
| `application_request_id` | Library: enrichment gap; `pgaudit.object_access` | The application request responsible for a database action. |
| `authenticated_principal` | Library: enrichment gap; `nginx.access`, `edge.waf_decision` | The authenticated user or service identity behind a request. |
| `badge_event_correlation` | Library: enrichment gap; `windows.security_events` | A link between a logical activity and a physical badge event. |
| `business_justification` | Library: enrichment gap; `object_store.access`, `smb.object_access` | The approved business reason for an operation. |
| `commands_executed_inside_the_job` | Library: enrichment gap; `github_actions.workflow_run` | The commands actually executed within a CI job. |
| `current_physical_presence` | Library: enrichment gap; `inventory.asset_register` | Whether a registered asset is physically present now. |
| `customer_contact_that_justified_it` | Library: enrichment gap; `ledger.adjustment_audit` | The customer interaction supporting the adjustment's justification. |
| `device_ownership` | Library: enrichment gap; `netflow.records` | The person or organization responsible for a device. |
| `device_posture` | Library: enrichment gap; `saml_idp.authentication` | The security or compliance state of the client device. |
| `device_trust_state` | Library: enrichment gap; `ad.authentication` | Whether the originating device meets the relevant trust requirements. |
| `downstream_application_action` | Library: enrichment gap; `saml_idp.authentication` | What the application did after authentication. |
| `downstream_database_statement` | Library: enrichment gap; `application.runtime_log` | The database statement issued as a result of an application request. |
| `end_user_on_whose_behalf` | Library: enrichment gap; `object_store.access` | The person on whose behalf a service performed an action. |
| `end_user_principal` | Library: enrichment gap; `pgaudit.object_access` | The end user behind an application or service account's activity. |
| `file_reads_inside_the_container` | Library: enrichment gap; `kubernetes.api_audit` | Which files were read within the container. |
| `file_sensitivity_label` | Library: enrichment gap; `smb.object_access` | The classification or sensitivity of an accessed file. |
| `image_provenance` | Library: enrichment gap; `container.file_access` | The origin and build history of the container image. |
| `in_container_process_activity` | Library: enrichment gap; `kubernetes.api_audit` | Processes and actions occurring inside a container. |
| `intent` | Library: enrichment gap; `agent_console.session_recording` | The purpose behind the agent's recorded actions. |
| `internal_account_context` | Library: enrichment gap; `fraud_engine.alert` | Relevant internal-account ownership, roles, or activity context. |
| `kubernetes_workload_identity` | Library: enrichment gap; `container.file_access` | The Kubernetes workload associated with a container or process. |
| `logical_account_of_the_same_person` | Library: enrichment gap; `badge.door_event` | The system account belonging to the badge holder. |
| `message_payload` | Library: enrichment gap; `kafka.authorizer` | The contents of a Kafka message. |
| `named_human_behind_a_shared_vendor_account` | Library: enrichment gap; `remote_access.session` | The individual using a shared vendor login. |
| `originating_physical_location` | Library: enrichment gap; `ad.authentication` | The physical location from which activity originated. |
| `payload` | Library: enrichment gap; `netflow.records` | The content carried by network traffic. |
| `physical_identity_of_the_person_at_the_device` | Library: enrichment gap; `network_device.aaa` | The actual person operating the device locally. |
| `physical_presence` | Library: enrichment gap; `windows.security_events` | Evidence that a person was physically present. |
| `producing_application_identity` | Library: enrichment gap; `kafka.authorizer` | The application that produced the message. |
| `relation_touched` | Library: enrichment gap; `postgres.session` | The database table, view, or other relation accessed. |
| `request_id` | Library: enrichment gap; `nginx.access` | An identifier linking a request to related records. |
| `requesting_workload_identity` | Library: enrichment gap; `vault.audit_device` | The application, job, or workload that requested the secret. |
| `seasonality_beyond_the_learning_period` | Library: enrichment gap; `baseline.redemption_velocity` | Seasonal patterns not represented in the baseline's training history. |
| `secret_value` | Library: enrichment gap; `vault.audit_device` | The actual secret contents, rather than its path or access record. |
| `secrets_accessed` | Library: enrichment gap; `github_actions.workflow_run` | Which secrets a workflow or job accessed. |
| `statement_text` | Library: enrichment gap; `postgres.session` | The actual database statement executed. |
| `supervisor_awareness` | Library: enrichment gap; `agent_console.session_recording` | Whether a supervisor knew about the agent's activity. |
| `tenant_id` | Library: enrichment gap; `nginx.access`, `postgres.session`, `pgaudit.object_access` | The tenant to which an event or resource belongs. |
| `tenant_scope_of_the_query` | Library: enrichment gap; `application.runtime_log` | Which tenants the application query was intended or permitted to access. |
| `the_ledger_event_it_relates_to` | Library: enrichment gap; `email.suppression_record` | The ledger event associated with a suppressed notification. |
| `the_ledger_events_the_customer_is_describing` | Library: enrichment gap; `complaints.queue_tickets` | The actual ledger events associated with a customer complaint. |
| `ticket_reference` | Library: enrichment gap; `ledger.adjustment_audit` | The support or approval ticket associated with an adjustment. |
| `use_of_the_credential_since_the_last_review` | Library: enrichment gap; `badge_audit.monthly_report` | Activity performed with the badge credential since its previous review. |
| `user_identity` | Library: enrichment gap; `netflow.records` | The user associated with network activity. |
| `visitor_escort_compliance` | Library: enrichment gap; `badge.door_event` | Whether a visitor was accompanied as required by policy. |
| `what_it_did` | Library: enrichment gap; `asset_audit.quarterly_report` | What the observed device actually did. |
| `what_the_footage_shows` | Library: enrichment gap; `cctv.retention_index` | The observed activity in the video, beyond its retention index. |
| `what_was_done_inside` | Library: enrichment gap; `badge.door_contact_alarm` | The activity performed inside the accessed physical space. |
| `when_the_device_appeared` | Library: enrichment gap; `asset_audit.quarterly_report` | When an observed device first became physically present. |
| `whether_a_work_order_authorised_it` | Library: enrichment gap; `hmi.operator_action` | Whether an approved work order permitted the operator action. |
| `whether_silence_means_no_activity_or_no_collection` | Library: enrichment gap; `collector.heartbeat` | Whether missing events reflect inactivity or a collection failure. |
| `whether_the_combination_was_ever_used_together` | Library: enrichment gap; `identity.role_assignment_export` | Whether maker and checker privileges were exercised together in practice. |
| `which_accounts_or_agents_caused_it` | Library: enrichment gap; `finance.points_liability_reconciliation` | The accounts or agents responsible for the reconciliation variance. |
| `which_operator_or_account_changed_it` | Library: enrichment gap; `historian.tag_change` | The operator or account responsible for changing the process value. |
| `who_initiated_the_redemption_internally` | Library: enrichment gap; `partner.settlement_file` | The internal person or account that initiated a redemption. |
| `who_opened_it` | Library: enrichment gap; `badge.door_contact_alarm` | The person who opened the door. |
| `why_the_score_was_assigned` | Library: enrichment gap; `fraud_engine.alert` | The reasons or contributing factors behind a fraud score. |
| `work_order_reference` | Library: enrichment gap; `remote_access.session` | The maintenance or work-order identifier authorizing a remote session. |

## LLM response 1: scm-runner-vault

Recorded model: `claude-opus-5`. Draft count: 5. Aliases rename the offered fields; they do not add observations.

### Node 0: T1078 - Source control - workflow run triggered by the same account that changed the workflow definition

Window: ``. Draft ID: `drf_15a0c32d00c7609b`.

| Descriptor | Origin | Short meaning |
|---|---|---|
| `principal` | LLM alias of `actor` | The account that triggered the workflow. |
| `repo` | LLM alias of `repository` | The source-code repository. |
| `branch` | LLM alias of `ref` | The Git reference; it can be a branch or tag, despite the generated alias branch. |
| `workflow` | LLM alias of `workflow_path` | The path to the workflow definition. |
| `runner` | LLM alias of `runner_name` | The runner that executed the workflow. |
| `outcome` | LLM alias of `conclusion` | The workflow run's reported outcome. |
| `self_authored_run` | LLM alias of `workflow_changed_and_run_by_same_actor` | Whether the same account changed a workflow definition and triggered its execution. |
| `note` | LLM explanatory entry | Explanatory guidance stored in the thresholds object; it is not a numeric threshold. Recorded value: No count threshold; each qualifying run is a candidate. If volume is high, group by principal and repo and surface principals new to that repo within a 24_hour review window. |

### Node 1: T1059 - Self-hosted build runner - shell execution inside a CI job correlated to a workflow run

Window: `15_min`. Draft ID: `drf_7bdbdbbaa9de2b7c`.

| Descriptor | Origin | Short meaning |
|---|---|---|
| `exec_path` | LLM alias of `process_path` | The executable path of the observed process. |
| `exec_args` | LLM alias of `process_args` | The process's command-line arguments. |
| `touched_file` | LLM alias of `file_path` | The file accessed by the process. |
| `container` | LLM alias of `container_id` | The identifier of the container involved. |
| `uid` | LLM alias of `user_id` | The process-associated user identifier. |
| `runner` | LLM alias of `runner_name` | The runner that executed the workflow. |
| `principal` | LLM alias of `actor` | The account that triggered the workflow. |
| `repo` | LLM alias of `repository` | The source-code repository. |
| `branch` | LLM alias of `ref` | The Git reference; it can be a branch or tag, despite the generated alias branch. |
| `workflow` | LLM alias of `workflow_path` | The path to the workflow definition. |
| `self_authored_run` | LLM alias of `workflow_changed_and_run_by_same_actor` | Whether the same account changed a workflow definition and triggered its execution. |
| `distinct_interpreters_per_container` | LLM threshold parameter | Number of different interpreter executable paths seen in one container; the draft alerts when the count exceeds 3. Recorded value: 3 |
| `grouping` | LLM explanatory entry | The fields and sometimes time intervals over which records should be grouped; it is not a numeric threshold. Recorded value: container_id, then runner_name |
| `baseline_note` | LLM explanatory entry | Instructions for establishing expected behavior before tuning the rule; it is not a numeric threshold. Recorded value: A baseline is needed of which interpreter paths and argument shapes each repository's jobs normally execute. Do not assume a universal normal; the same shell invocation is routine on a build runner and anomalous only relative to that repository's history. |

### Node 2: T1572 - Self-hosted build runner - tunnelling client launched from a CI job

Window: `10_min`. Draft ID: `drf_c883ed73610e5c89`.

| Descriptor | Origin | Short meaning |
|---|---|---|
| `exec_path` | LLM alias of `process_path` | The executable path of the observed process. |
| `exec_args` | LLM alias of `process_args` | The process's command-line arguments. |
| `touched_file` | LLM alias of `file_path` | The file accessed by the process. |
| `container` | LLM alias of `container_id` | The identifier of the container involved. |
| `uid` | LLM alias of `user_id` | The process-associated user identifier. |
| `runner` | LLM alias of `runner_name` | The runner that executed the workflow. |
| `repo` | LLM alias of `repository` | The source-code repository. |
| `branch` | LLM alias of `ref` | The Git reference; it can be a branch or tag, despite the generated alias branch. |
| `workflow` | LLM alias of `workflow_path` | The path to the workflow definition. |
| `principal` | LLM alias of `actor` | The account that triggered the workflow. |
| `outcome` | LLM alias of `conclusion` | The workflow run's reported outcome. |
| `grouping` | LLM explanatory entry | The fields and sometimes time intervals over which records should be grouped; it is not a numeric threshold. Recorded value: container_id |
| `baseline_note` | LLM explanatory entry | Instructions for establishing expected behavior before tuning the rule; it is not a numeric threshold. Recorded value: Build an allowlist of tunnelling or remote-access binaries that are a declared part of specific pipelines, keyed by repository and workflow_path. Treat everything else as unexpected rather than assuming a global normal. |

### Node 3: T1046 - Secrets manager - unauthenticated probing of Vault API paths

Window: `10_min`. Draft ID: `drf_64dbc1eabaff4ff4`.

| Descriptor | Origin | Short meaning |
|---|---|---|
| `req_id` | LLM alias of `request.id` | The Vault request identifier. |
| `principal` | LLM alias of `auth.display_name` | The identity display name recorded by Vault; uniqueness must be checked. |
| `policies` | LLM alias of `auth.policies` | The policies attached to the Vault identity. |
| `path` | LLM alias of `request.path` | The requested Vault API or secret path. |
| `operation` | LLM alias of `request.operation` | The requested Vault operation. |
| `status` | LLM alias of `response.status` | The response status offered by the library for Vault. |
| `distinct_paths_per_principal` | LLM threshold parameter | Number of different Vault paths requested by an identity; the draft alerts above 15 in 10 minutes. Recorded value: 15 |
| `denied_or_error_responses_per_principal` | LLM threshold parameter | Number of denied or error Vault responses per identity; the draft alerts above 20 in 10 minutes. Recorded value: 20 |
| `grouping` | LLM explanatory entry | The fields and sometimes time intervals over which records should be grouped; it is not a numeric threshold. Recorded value: auth.display_name within a 10_min window |
| `baseline_note` | LLM explanatory entry | Instructions for establishing expected behavior before tuning the rule; it is not a numeric threshold. Recorded value: Health-check pollers will dominate this data. Baseline the normal per-principal rate of distinct request.path values and the normal error ratio for each known caller before setting these numbers; the values given are starting parameters, not an asserted norm. |

### Node 4: T1210 - Secrets manager - anomalous secret read volume or error-then-success pattern on Vault

Window: `60_sec`. Draft ID: `drf_14a06508fc56cf64`.

| Descriptor | Origin | Short meaning |
|---|---|---|
| `req_id` | LLM alias of `request.id` | The Vault request identifier. |
| `principal` | LLM alias of `auth.display_name` | The identity display name recorded by Vault; uniqueness must be checked. |
| `policies` | LLM alias of `auth.policies` | The policies attached to the Vault identity. |
| `path` | LLM alias of `request.path` | The requested Vault API or secret path. |
| `operation` | LLM alias of `request.operation` | The requested Vault operation. |
| `status` | LLM alias of `response.status` | The response status offered by the library for Vault. |
| `read_rate` | LLM alias of `secret_read_rate_per_principal` | Number of secret reads by an identity per defined time interval. |
| `read_rate_multiple_of_baseline` | LLM threshold parameter | Multiplier applied to the principal's historical secret-read rate; the proposed multiplier is 5. Recorded value: 5 |
| `distinct_secret_paths_per_principal_per_window` | LLM threshold parameter | Number of different secret paths read by an identity; the draft alerts above 10 per 60-second window. Recorded value: 10 |
| `failed_then_successful_paths` | LLM threshold parameter | Number of distinct Vault paths with a failed read followed by a successful read by the same identity; proposed minimum 3 within a 24-hour rollup. Recorded value: 3 |
| `grouping` | LLM explanatory entry | The fields and sometimes time intervals over which records should be grouped; it is not a numeric threshold. Recorded value: auth.display_name, evaluated per 60_sec window and rolled up over 24_hour |
| `baseline_note` | LLM explanatory entry | Instructions for establishing expected behavior before tuning the rule; it is not a numeric threshold. Recorded value: The read-rate baseline must be per principal and per hour-of-day, since CI callers are bursty around deployments. The multiples above are starting parameters; a universal normal rate does not exist for this estate. |

## LLM response 2: web-console-telemetry

Recorded model: `claude-opus-5`. Draft count: 4. Aliases rename the offered fields; they do not add observations.

### Node 0: T1190 - Customer console - Exploitation attempt against internet-facing web console

Window: `10_min`. Draft ID: `drf_753eee3b75db9ca3`.

| Descriptor | Origin | Short meaning |
|---|---|---|
| `http_route` | LLM alias of `route` | The application route handling the request. |
| `http_verb` | LLM alias of `method` | The HTTP request method. |
| `response_status` | LLM alias of `status` | The application response status. |
| `actor` | LLM alias of `principal` | The user or service identity recorded by the application. |
| `correlation_id` | LLM alias of `request_id` | The application request identifier, used to correlate related records. |
| `handling_ms` | LLM alias of `duration_ms` | The request handling time in milliseconds. |
| `route_is_new_for_actor` | LLM alias of `first_time_route_for_principal` | Whether an application route is new in the observed history of this user or service identity. |
| `error_status_requests_per_principal` | LLM threshold parameter | Number of responses with HTTP status at least 500 for an identity; proposed minimum 8 in 10 minutes. Recorded value: 8 |
| `distinct_new_routes_per_principal` | LLM threshold parameter | Number of routes newly observed for an identity; proposed minimum 3 in 10 minutes, with an additional error-response condition. Recorded value: 3 |
| `duration_ms_multiple_of_route_median` | LLM threshold parameter | Request-duration multiplier relative to the route's baseline median; proposed value 5 for severity escalation. Recorded value: 5 |

### Node 1: T1505.003 - Customer console - Web shell route served by the application

Window: `60_min`. Draft ID: `drf_b7e1b5c20768c7ad`.

| Descriptor | Origin | Short meaning |
|---|---|---|
| `http_route` | LLM alias of `route` | The application route handling the request. |
| `http_verb` | LLM alias of `method` | The HTTP request method. |
| `response_status` | LLM alias of `status` | The application response status. |
| `actor` | LLM alias of `principal` | The user or service identity recorded by the application. |
| `correlation_id` | LLM alias of `request_id` | The application request identifier, used to correlate related records. |
| `handling_ms` | LLM alias of `duration_ms` | The request handling time in milliseconds. |
| `route_is_new_for_actor` | LLM alias of `first_time_route_for_principal` | Whether an application route is new in the observed history of this user or service identity. |
| `successful_requests_to_new_route` | LLM threshold parameter | Successful responses on a route new to the identity; proposed minimum 5 in 60 minutes, with other conditions. Recorded value: 5 |
| `duration_ms_spread_ratio` | LLM threshold parameter | Ratio of maximum to minimum request duration in the group, with the minimum floored at 1 ms; proposed value 10. Recorded value: 10 |

### Node 2: T1552.001 - Customer console - Credential file read through application request path

Window: `30_min`. Draft ID: `drf_08bc97bdbc7e5e8d`.

| Descriptor | Origin | Short meaning |
|---|---|---|
| `http_route` | LLM alias of `route` | The application route handling the request. |
| `http_verb` | LLM alias of `method` | The HTTP request method. |
| `response_status` | LLM alias of `status` | The application response status. |
| `actor` | LLM alias of `principal` | The user or service identity recorded by the application. |
| `correlation_id` | LLM alias of `request_id` | The application request identifier, used to correlate related records. |
| `handling_ms` | LLM alias of `duration_ms` | The request handling time in milliseconds. |
| `route_is_new_for_actor` | LLM alias of `first_time_route_for_principal` | Whether an application route is new in the observed history of this user or service identity. |
| `duration_ms_zscore_vs_route_baseline` | LLM threshold parameter | How many baseline standard deviations the duration lies above the route's mean; proposed minimum 4. Recorded value: 4 |
| `minimum_successful_requests` | LLM threshold parameter | Minimum qualifying successful requests sharing a principal; proposed value 2 in 30 minutes. Recorded value: 2 |

### Node 3: T1210 - Telemetry warehouse - Anomalous service-credential session and object access on PostgreSQL

Window: `60_min`. Draft ID: `drf_c0ece411ed123316`.

| Descriptor | Origin | Short meaning |
|---|---|---|
| `db_user` | LLM alias of `user` | The database session user. |
| `db_name` | LLM alias of `database` | The database used by the session. |
| `client_address` | LLM alias of `client_addr` | The client's network address. |
| `client_app` | LLM alias of `application_name` | The client-supplied application name recorded for the session. |
| `session_key` | LLM alias of `session_id` | The database session identifier used to join records. |
| `session_duration` | LLM alias of `duration` | The database session duration; the unit must follow the source definition. |
| `stmt_key` | LLM alias of `statement_id` | The identifier of the audited statement. |
| `object` | LLM alias of `object_name` | The database object accessed. |
| `operation` | LLM alias of `command_tag` | The type of database command. |
| `statement_text` | LLM alias of `statement` | The SQL statement recorded by the audit source. |
| `rows_estimate` | LLM alias of `rows_touched_estimate` | Approximate number of database rows affected or accessed; the estimation method must be defined. |
| `distinct_objects_per_session` | LLM threshold parameter | Number of different database objects accessed in a session; proposed minimum 10. Recorded value: 10 |
| `rows_touched_estimate_per_session` | LLM threshold parameter | Sum of estimated rows touched within a database session; proposed minimum 100000. Recorded value: 100000 |
| `allowed_client_app_values` | LLM threshold parameter | Uncertain: apparently the expected number of approved client application-name values, set to 1. The pseudocode checks membership in an approved set and never uses this numeric parameter. Recorded value: 1 |

## Interpretation limits found in this output

- allowed_client_app_values is not operationally defined by the pseudocode; do not treat its value 1 as an implemented allowlist or tested constraint.
- The Vault-probing draft refers to a lower distinct-path threshold for an anonymous caller but does not supply a separate numeric value for it.
- branch is an alias of Git ref, which may also identify a tag. principal in the Vault drafts comes from auth.display_name; a display name is not automatically a stable unique identity.
- correlation_id renames request_id; it does not prove downstream systems propagate that identifier. rows_estimate renames a declared estimate; it does not establish how rows are counted.
- first_time_route_for_principal needs a defined history period, route normalization, identity handling, and cold-start policy. The library name does not provide those rules.
- The numeric values are generated starting points. Their units, grouping, comparison operators, baseline requirements, and test evidence must be retained when translating a draft into a working analytic.
