from pathlib import Path

from r2d2.storage import ChatDAO, Database


def test_chat_dao_persists_sessions_and_messages(tmp_path: Path):
    db_path = tmp_path / 'r2d2.db'
    database = Database(db_path)
    dao = ChatDAO(database)

    session = dao.get_or_create_session('/tmp/a.out', trajectory_id='traj-1', title='Sample binary')
    assert session.message_count == 0
    assert session.trajectory_id == 'traj-1'

    message = dao.append_message(session.session_id, 'system', 'Analysis complete', attachments=[{'type': 'analysis_result'}])
    assert message.role == 'system'

    messages = dao.list_messages(session.session_id)
    assert len(messages) == 1
    assert messages[0].content == 'Analysis complete'

    updated = dao.get_or_create_session('/tmp/a.out')
    assert updated.session_id == session.session_id
    assert updated.message_count == 1

    sessions = dao.list_sessions()
    assert sessions
