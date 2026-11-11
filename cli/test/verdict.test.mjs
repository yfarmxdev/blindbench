import test from 'node:test';
import assert from 'node:assert/strict';
import { checklistVerdict, scoreChecklist, scoreChecklistV2 } from '../lib/grade.mjs';

const item = { checklist: [
  { id: 'bolt', finding: 'the anchor bolts are one size too small', severity: 'high' },
  { id: 'drain', finding: 'the drawing shows no roof drain', severity: 'high' },
] };
const answer = 'The anchor bolts are one size too small for the load. The drawing shows no roof drain at all.';
const full = '{"results":[{"id":"bolt","quote":"The anchor bolts are one size too small","found":true,"candidate_severity":"high"},' +
  '{"id":"drain","quote":"The drawing shows no roof drain","found":true,"candidate_severity":"high"}],"decoys":[]}';

test('a judge verdict cut off at the token limit is refused, not scored as nothing found', () => {
  assert.equal(scoreChecklistV2(item, full, answer).score, 1);
  // The same verdict, cut off inside the second finding: it still holds one complete inner object.
  const cut = full.slice(0, full.indexOf('"drain"') + 30);
  assert.throws(() => checklistVerdict(cut), /incomplete/);
  assert.throws(() => scoreChecklistV2(item, cut, answer), /incomplete/);
  assert.throws(() => scoreChecklist(item, cut, { answer }), /incomplete/);
  // Thinking aloud with braces before a complete verdict is still fine, and so is a decoys-only reply.
  assert.equal(scoreChecklistV2(item, 'Let me check {each finding}. ' + full, answer).score, 1);
  assert.deepEqual(checklistVerdict('{"decoys":[]}'), { decoys: [] });
  assert.throws(() => checklistVerdict('no verdict here'), /JSON/);
});
