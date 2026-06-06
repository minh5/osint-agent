import sys
import logging
import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main():
    config.validate()

    if len(sys.argv) < 2:
        print("Usage: uv run python main.py \"<input>\"")
        print("  Single:   uv run python main.py \"email@example.com\"")
        print("  Multiple: uv run python main.py \"email@example.com\\nJohn Doe\\n555-123-4567\"")
        sys.exit(1)

    raw_input = sys.argv[1]

    from agent.graph import build_graph
    from models.shared import PipelineState

    graph = build_graph()
    initial_state = PipelineState(raw_input=raw_input)

    logger.info("Starting OSINT pipeline")
    final_state = graph.invoke(initial_state)
    logger.info("Pipeline complete")


if __name__ == "__main__":
    main()
