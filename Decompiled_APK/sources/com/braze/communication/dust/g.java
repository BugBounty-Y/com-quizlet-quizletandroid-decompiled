package com.braze.communication.dust;

import com.braze.AbstractC1484j;
import com.braze.managers.x;
import java.net.HttpURLConnection;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public J a;
    public J b;
    public int c;
    public /* synthetic */ Object d;
    public final /* synthetic */ h e;
    public final /* synthetic */ x f;
    public final /* synthetic */ String g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, x xVar, String str, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.e = hVar;
        this.f = xVar;
        this.g = str;
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Starting DUST stream to ", str);
    }

    public static final String b() {
        return "Caught unexpected exception listening to DUST stream";
    }

    public static final String c() {
        return "Stream connection job cancelled";
    }

    public static final String d() {
        return "Closing stream connection data";
    }

    public static final String e() {
        return "Stream job finished";
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        g gVar = new g(this.e, this.f, this.g, hVar);
        gVar.d = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00db  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x011e A[Catch: all -> 0x001c, TryCatch #7 {all -> 0x001c, blocks: (B:7:0x0017, B:38:0x00dd, B:52:0x0118, B:54:0x011e, B:55:0x0133), top: B:66:0x0017 }] */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0133 A[Catch: all -> 0x001c, TRY_LEAVE, TryCatch #7 {all -> 0x001c, blocks: (B:7:0x0017, B:38:0x00dd, B:52:0x0118, B:54:0x011e, B:55:0x0133), top: B:66:0x0017 }] */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0162 A[PHI: r0
  0x0162: PHI (r0v14 java.net.HttpURLConnection) = (r0v11 java.net.HttpURLConnection), (r0v18 java.net.HttpURLConnection) binds: [B:57:0x0160, B:40:0x0101] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0194  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r21) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 408
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.communication.dust.g.invokeSuspend(java.lang.Object):java.lang.Object");
    }

    public static final String a(J j) {
        return "DUST stream response code " + ((HttpURLConnection) j.a).getResponseCode();
    }

    public static final String a() {
        return "Stream job coroutine no longer active";
    }
}
