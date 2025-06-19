package com.google.firebase.sessions.settings;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public J j;
    public J k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ e n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        c cVar = new c(this.n, hVar);
        cVar.m = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((JSONObject) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:68:0x015a, code lost:
    
        if (r13 == r4) goto L84;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x01ab, code lost:
    
        if (r13 == r4) goto L84;
     */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00e4  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00ec  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x013c  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0160  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0163  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x01a9  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 452
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.settings.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
