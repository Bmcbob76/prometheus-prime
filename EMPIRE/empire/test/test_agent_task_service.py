def test_create_task_no_user_id(client, session_local, agent, main, models):
    with session_local.begin() as db:
        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        resp, err = main.agenttasksv2.create_task_shell(
            db, db_agent, "echo 'hi'", True, 0
        )

        assert err is None
        assert resp.user_id is None
        assert resp.user is None
