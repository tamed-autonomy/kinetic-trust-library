"""Retained gates recheck current authority; replacing a token changes binding."""
def check_adjudication_checkpoint(test,verifier,current,body,sign,operation,fixtures,advance):
    import json,hashlib,rfc8785
    native=verifier.consumer.clearance_verifier.native_verifier
    required={json.loads(a.profile_bytes)["gate_id"] for a in current.native_result.adjudications if a.gate_required}
    selected=next((f for f in fixtures if f["profile"]["gate_id"] in required),None)
    if selected is None:return
    payload=json.loads(rfc8785.dumps(selected["payload"]));original_body=json.loads(rfc8785.dumps(body))
    gate_id=selected["profile"]["gate_id"];order=json.loads(verifier.consumer.profile_bytes)["prerequisite_order"]
    index=order.index("adjudication:"+gate_id)
    original_raw=sign()
    def kwargs(token):
        if native.adjudication_verifier is not None:return dict(adjudication_token=token)
        tokens={json.loads(a.profile_bytes)["gate_id"]:a.token_bytes for a in current.native_result.adjudications if a.token_bytes is not None}
        tokens[gate_id]=token;return dict(adjudication_tokens=tuple(tokens.items()))
    def evaluate(raw,token,now=1001):return verifier.evaluate(raw,current,actual_operation=operation,
        invocation_evidence=b"fixture-actual-invocation",evaluated_at=now,clock_healthy=True,**kwargs(token))
    try:
        selected["payload"].update(jti="replacement-current",iat=1001)
        token=selected["sign"]()
        test.assertFalse(evaluate(original_raw,token).conditional_consumption)
        body["prerequisite_digests"][index]="sha256:"+hashlib.sha256(token).hexdigest()
        backdated=evaluate(sign(),token)
        test.assertEqual(backdated.consumption.reason,"SOFTWARE_EVALUATION_PRECEDES_INPUTS")
        body["evaluated_at"]=1001
        test.assertTrue(evaluate(sign(),token).conditional_consumption)
        selected["payload"]["exp"]=1002;token=selected["sign"]()
        body["prerequisite_digests"][index]="sha256:"+hashlib.sha256(token).hexdigest()
        test.assertEqual(evaluate(sign(),token).consumption.reason,"SOFTWARE_VALIDITY_WIDENED")
        body["expires_at"]=1002
        test.assertTrue(evaluate(sign(),token).conditional_consumption)
        advance(1002)
        expired=evaluate(sign(),token,1002)
        test.assertFalse(expired.conditional_consumption);test.assertEqual(expired.native_result.reason,"ADJ_GATE_UNSATISFIED")
        advance(1001);selected["payload"].clear();selected["payload"].update(payload)
        body.clear();body.update(json.loads(rfc8785.dumps(original_body)))
        selected["adapter"].invalid=True
        revoked=verifier.evaluate(original_raw,current,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1001,clock_healthy=True)
        test.assertFalse(revoked.conditional_consumption);test.assertEqual(revoked.native_result.reason,"ADJ_GATE_UNSATISFIED")
    finally:
        advance(1001);selected["payload"].clear();selected["payload"].update(payload);selected["adapter"].invalid=False
        body.clear();body.update(original_body)
