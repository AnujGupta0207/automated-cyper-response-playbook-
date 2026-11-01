import json
from sentence_transformers import SentenceTransformer, util


# Load the cybersecurity knowledge base
with open("knowledge_base/mitre_techniques.json", "r") as file:
    knowledge_base = json.load(file)


# Load a local embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")


def retrieve_knowledge(query, top_k=2):

    documents = []

    for item in knowledge_base:
        text = (
            f"Technique: {item['technique_name']}\n"
            f"ID: {item['technique_id']}\n"
            f"Description: {item['description']}\n"
            f"Detection: {item['detection']}\n"
            f"Response: {', '.join(item['response'])}"
        )

        documents.append(text)

    # Convert query and documents into embeddings
    query_embedding = model.encode(query, convert_to_tensor=True)
    document_embeddings = model.encode(documents, convert_to_tensor=True)

    # Calculate similarity
    scores = util.cos_sim(query_embedding, document_embeddings)[0]

    # Get the most relevant documents
    top_results = scores.topk(k=min(top_k, len(documents)))

    results = []

    for index in top_results.indices:
        results.append(documents[index])

    return results


# Test the RAG system
if __name__ == "__main__":

    query = "Multiple failed login attempts against an administrator account"

    results = retrieve_knowledge(query)

    print("\nRetrieved Cybersecurity Knowledge:\n")

    for result in results:
        print(result)
        print("-" * 60)