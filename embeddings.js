/**
 * Embedding Service - Local vector embeddings using transformers.js
 * Uses all-MiniLM-L6-v2 (384-dim) for sentence embeddings
 * Model downloads automatically on first use (~23MB), cached thereafter
 */

let pipeline = null;
let embeddingPipeline = null;

async function getEmbeddingPipeline() {
  if (embeddingPipeline) return embeddingPipeline;

  if (!pipeline) {
    const { pipeline: pipelineFn } = await import('@xenova/transformers');
    pipeline = pipelineFn;
  }

  console.log('Loading embedding model (first time may take a moment)...');
  embeddingPipeline = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2');
  console.log('Embedding model loaded');
  return embeddingPipeline;
}

/**
 * Generate a 384-dimensional embedding for a text string
 * @param {string} text
 * @returns {Promise<number[]>}
 */
async function generateEmbedding(text) {
  const pipe = await getEmbeddingPipeline();
  const output = await pipe(text, { pooling: 'mean', normalize: true });
  return Array.from(output.data);
}

/**
 * Compute cosine similarity between two embedding vectors
 * @param {number[]} a
 * @param {number[]} b
 * @returns {number} similarity score between -1 and 1
 */
function cosineSimilarity(a, b) {
  let dot = 0, magA = 0, magB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }
  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  return denom === 0 ? 0 : dot / denom;
}

module.exports = { generateEmbedding, cosineSimilarity };
