from app.agent.agent import SecurityAgent


if __name__ == "__main__":
    agent = SecurityAgent("demo_app")
    for event in agent.run():
        print(f"[{event.stage}] {event.message}")
    agent.save_cache()
    print("Cache written to cache/last_run.json")
    print(f"Risk: {agent.risk_before} -> {agent.risk_after}")
