use super::*;

const PASSWORD_PROMPT: &str = "alice@server's password: ";
const HOST_PROMPT: &str = "The authenticity of host 'server' can't be established.\nED25519 key fingerprint is SHA256:trusted-fixture.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ";

struct FixedPrompter {
    calls: AtomicUsize,
    decline: bool,
}

#[async_trait]
impl PromptHandler for FixedPrompter {
    async fn request(
        &self,
        owner: &str,
        _host: &str,
        kind: PromptKind,
        _prompt: &str,
    ) -> Option<Zeroizing<String>> {
        assert_eq!(owner, "test-window");
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.decline {
            return None;
        }
        Some(Zeroizing::new(
            if kind == PromptKind::HostKey {
                "yes"
            } else {
                " test-secret "
            }
            .into(),
        ))
    }
}

fn context(decline: bool) -> (ServerContext, Arc<FixedPrompter>) {
    let prompter = Arc::new(FixedPrompter {
        calls: AtomicUsize::new(0),
        decline,
    });
    (
        ServerContext {
            token: "capability".into(),
            host: "server".into(),
            owner_window: "test-window".into(),
            prompter: prompter.clone(),
            credentials: Arc::new(CredentialCache::default()),
            failure: Arc::new(Mutex::new(None)),
            requests: AtomicUsize::new(0),
            seen: Arc::new(Mutex::new(HashSet::new())),
        },
        prompter,
    )
}

#[test]
fn classifies_only_supported_openssh_prompts() {
    assert_eq!(prompt_kind(PASSWORD_PROMPT), Some(PromptKind::Password));
    assert_eq!(
        prompt_kind("Enter passphrase for key 'C:\\Users\\Alice\\.ssh\\id_ed25519': "),
        Some(PromptKind::Passphrase)
    );
    assert_eq!(prompt_kind(HOST_PROMPT), Some(PromptKind::HostKey));
    assert_eq!(prompt_kind("Enter OTP:"), None);
    assert_eq!(
        prompt_kind("Are you sure you want to continue connecting?"),
        None
    );
}

#[tokio::test]
async fn caches_exact_prompts_but_never_host_key_approvals() {
    let (context, prompter) = context(false);
    assert_eq!(
        context.answer(PASSWORD_PROMPT).await.unwrap().as_str(),
        " test-secret "
    );
    context.seen.lock().unwrap().clear(); // the next SSH invocation
    context.answer(PASSWORD_PROMPT).await.unwrap();
    assert_eq!(prompter.calls.load(Ordering::Relaxed), 1);
    context.answer("bob@jump-host's password: ").await.unwrap();
    assert_eq!(prompter.calls.load(Ordering::Relaxed), 2);
    assert!(!context
        .credentials
        .redact("echo  test-secret ")
        .contains("test-secret"));
    context.answer(HOST_PROMPT).await.unwrap();
    context.answer(HOST_PROMPT).await.unwrap();
    assert_eq!(prompter.calls.load(Ordering::Relaxed), 4);
    assert!(!context
        .credentials
        .answers
        .lock()
        .unwrap()
        .contains_key(HOST_PROMPT));
    assert!(
        context.credentials.answers.lock().unwrap().is_empty(),
        "new host trust clears old credentials"
    );
    context.credentials.clear();
    assert!(context.credentials.answers.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cancellation_does_not_nag_again_during_background_reconnect() {
    let (context, prompter) = context(true);
    assert!(context.answer(PASSWORD_PROMPT).await.is_none());
    assert!(context.answer(PASSWORD_PROMPT).await.is_none());
    assert_eq!(prompter.calls.load(Ordering::Relaxed), 1);
    assert!(context.failure.lock().unwrap().is_some());
}

#[tokio::test]
async fn unrecognized_challenges_never_receive_a_password() {
    let (context, prompter) = context(false);
    context.answer(PASSWORD_PROMPT).await.unwrap();
    assert!(context.answer("Authentication code: ").await.is_none());
    assert_eq!(prompter.calls.load(Ordering::Relaxed), 1);
}

fn pending(
    broker: &PromptBroker,
    kind: PromptKind,
    expires_at: i64,
) -> oneshot::Receiver<Option<Zeroizing<String>>> {
    let (response, receiver) = oneshot::channel();
    broker.pending.lock().unwrap().insert(
        "request".into(),
        PendingPrompt {
            payload: PromptPayload {
                request_id: "request".into(),
                owner_window: "owner".into(),
                host: "server".into(),
                kind,
                prompt: PASSWORD_PROMPT.into(),
                expires_at,
            },
            response,
        },
    );
    receiver
}

#[tokio::test]
async fn only_the_owner_may_inspect_or_answer_a_request() {
    let broker = PromptBroker::default();
    let receiver = pending(&broker, PromptKind::Password, i64::MAX);
    assert!(broker.list("other").is_empty());
    assert_eq!(broker.list("owner").len(), 1);
    assert!(broker
        .answer("other", "request", Some("wrong-window".into()))
        .is_err());
    assert_eq!(broker.list("owner").len(), 1);
    broker
        .answer("owner", "request", Some(" secret ".into()))
        .unwrap();
    assert_eq!(receiver.await.unwrap().unwrap().as_str(), " secret ");
    assert!(broker.list("owner").is_empty());
}

#[tokio::test]
async fn host_approval_is_explicit_and_expired_answers_fail_closed() {
    let broker = PromptBroker::default();
    let receiver = pending(&broker, PromptKind::HostKey, i64::MAX);
    assert!(broker
        .answer("owner", "request", Some("true".into()))
        .is_err());
    broker.answer("owner", "request", None).unwrap();
    assert!(receiver.await.unwrap().is_none());
    let receiver = pending(&broker, PromptKind::Password, 0);
    broker
        .answer("owner", "request", Some("late-secret".into()))
        .unwrap();
    assert!(receiver.await.unwrap().is_none());
}

#[tokio::test]
async fn helper_socket_requires_the_ephemeral_capability() {
    let (_, prompter) = context(false);
    let server = AskpassServer::start(
        PathBuf::from("codeg.exe"),
        "server".into(),
        "test-window".into(),
        prompter.clone(),
        Arc::new(CredentialCache::default()),
    )
    .await
    .unwrap();
    for (token, expected) in [
        ("wrong-token".to_string(), false),
        (server.token.clone(), true),
    ] {
        let mut socket = TcpStream::connect(&server.address).await.unwrap();
        let mut request = serde_json::to_vec(&AskpassRequest {
            token,
            prompt: PASSWORD_PROMPT.into(),
        })
        .unwrap();
        request.push(b'\n');
        socket.write_all(&request).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        if expected {
            let reply: super::super::askpass_client::AskpassReply =
                serde_json::from_slice(&response).unwrap();
            assert_eq!(reply.answer.as_deref(), Some(" test-secret "));
        } else {
            assert!(response.is_empty());
        }
    }
    assert_eq!(prompter.calls.load(Ordering::Relaxed), 1);
    let command = crate::ssh::command::ssh_command_with_askpass(
        &crate::models::RemoteWorkspaceSshConfig {
            host: "server".into(),
            ..Default::default()
        },
        crate::ssh::command::SshInvocation::Exec,
        Some("true"),
        Some(&server),
    );
    // No actual password in process inspection, shell commands or environment.
    for argument in command.as_std().get_args() {
        assert!(!argument.to_string_lossy().contains("test-secret"));
    }
    for (_, value) in command.as_std().get_envs() {
        assert!(!value
            .unwrap_or_default()
            .to_string_lossy()
            .contains("test-secret"));
    }
    let address = server.address.clone();
    drop(server);
    tokio::time::timeout(Duration::from_secs(2), async {
        while TcpStream::connect(&address).await.is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn identical_prompts_from_multiple_hops_are_never_reused() {
    let (context, prompter) = context(false);
    context.answer(PASSWORD_PROMPT).await.unwrap();
    context.answer(PASSWORD_PROMPT).await.unwrap();
    assert_eq!(prompter.calls.load(Ordering::Relaxed), 2);
    assert!(context.credentials.answers.lock().unwrap().is_empty());
    context.seen.lock().unwrap().clear();
    context.answer(PASSWORD_PROMPT).await.unwrap();
    assert_eq!(prompter.calls.load(Ordering::Relaxed), 3);
}
