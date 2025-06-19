package com.braze.communication.dust;

import androidx.compose.animation.d0;
import com.braze.AbstractC1476b;
import com.braze.AbstractC1484j;
import com.braze.C1481g;
import com.braze.W;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.managers.x;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import kotlin.coroutines.n;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class h {
    public static final String b = BrazeLogger.getBrazeLogTag((Class<?>) h.class);
    public InterfaceC5025j0 a;

    public static final String a(String str) {
        return AbstractC1476b.a("Received new line: '", str, '\'');
    }

    public static final String b(String str) {
        return AbstractC1484j.a("Got un-actionable stream line:\n", str);
    }

    public static final String c(String str) {
        return AbstractC1484j.a("Failed to parse data line:\n", str);
    }

    public static final String d(String str) {
        return AbstractC1484j.a("Got call to startStream() for url ", str);
    }

    public static final String a(h hVar) {
        return "Got call to endStream(). Stream job: " + hVar.a;
    }

    public static final String c(h hVar) {
        return "Not restarting stream since " + hVar.a + " is still active.";
    }

    public static final String d(h hVar) {
        return "Started stream job " + hVar.a;
    }

    public final void b() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(this, 2), 7, (Object) null);
        InterfaceC5025j0 interfaceC5025j0 = this.a;
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(null);
        }
        this.a = null;
    }

    public final void a(String url, x ingestor, boolean z) throws Throwable {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(ingestor, "ingestor");
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new W(url, 10), 7, (Object) null);
        if (z && this.a != null) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(this, 0), 7, (Object) null);
            return;
        }
        E.D(n.a, new e(this, null));
        this.a = E.A(BrazeCoroutineScope.INSTANCE, null, null, new g(this, ingestor, url, null), 3);
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(this, 1), 7, (Object) null);
    }

    public static final String b(J j) {
        return "Recorded data type: " + ((String) j.a);
    }

    public static final String b(h hVar) {
        return "Got call to endStreamAndJoin(). Stream job: " + hVar.a;
    }

    public static final String b(String str, String str2) {
        return "Not handling event: '" + str + "' and data: '" + str2 + '\'';
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:17:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0168  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /* JADX WARN: Type inference failed for: r8v3, types: [kotlin.jvm.functions.Function1] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:20:0x009d -> B:21:0x00a2). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlinx.coroutines.C r22, kotlinx.coroutines.channels.w r23, com.braze.managers.x r24, kotlin.coroutines.jvm.internal.c r25) {
        /*
            Method dump skipped, instructions count: 363
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.communication.dust.h.a(kotlinx.coroutines.C, kotlinx.coroutines.channels.w, com.braze.managers.x, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final String a() {
        return "Waiting to consume new line";
    }

    public static final String a(J j) {
        return "Recorded event type: " + ((String) j.a);
    }

    public static final String a(J j, J j2) {
        StringBuilder sb = new StringBuilder("Handling full event on blank line. lastEventType: '");
        sb.append((String) j.a);
        sb.append("' \ndata: '");
        return d0.r(sb, (String) j2.a, '\'');
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r14) {
        /*
            r13 = this;
            boolean r0 = r14 instanceof com.braze.communication.dust.b
            if (r0 == 0) goto L13
            r0 = r14
            com.braze.communication.dust.b r0 = (com.braze.communication.dust.b) r0
            int r1 = r0.d
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.d = r1
            goto L18
        L13:
            com.braze.communication.dust.b r0 = new com.braze.communication.dust.b
            r0.<init>(r13, r14)
        L18:
            java.lang.Object r14 = r0.b
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.d
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            com.braze.communication.dust.h r0 = r0.a
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L70
        L2c:
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r14.<init>(r0)
            throw r14
        L34:
            com.braze.communication.dust.h r2 = r0.a
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L60
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.braze.support.BrazeLogger r5 = com.braze.support.BrazeLogger.INSTANCE
            java.lang.String r6 = com.braze.communication.dust.h.b
            com.braze.communication.dust.k r10 = new com.braze.communication.dust.k
            r14 = 3
            r10.<init>(r13, r14)
            r8 = 0
            r9 = 0
            r7 = 0
            r11 = 14
            r12 = 0
            com.braze.support.BrazeLogger.brazelog$default(r5, r6, r7, r8, r9, r10, r11, r12)
            kotlinx.coroutines.j0 r14 = r13.a
            if (r14 == 0) goto L6f
            r0.a = r13
            r0.d = r4
            java.lang.Object r14 = kotlinx.coroutines.E.k(r14, r0)
            if (r14 != r1) goto L5f
            goto L6c
        L5f:
            r2 = r13
        L60:
            r0.a = r2
            r0.d = r3
            r3 = 50
            java.lang.Object r14 = kotlinx.coroutines.E.n(r3, r0)
            if (r14 != r1) goto L6d
        L6c:
            return r1
        L6d:
            r0 = r2
            goto L70
        L6f:
            r0 = r13
        L70:
            r14 = 0
            r0.a = r14
            kotlin.Unit r14 = kotlin.Unit.a
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.communication.dust.h.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static void a(String str, String str2, Function1 function1) {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        String str3 = b;
        BrazeLogger.brazelog$default(brazeLogger, str3, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(4, str, str2), 14, (Object) null);
        if (Intrinsics.b(str, "msg")) {
            try {
                JSONObject jSONObject = new JSONObject(str2);
                BrazeLogger.brazelog$default(brazeLogger, str3, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new j(jSONObject, 0), 14, (Object) null);
                function1.invoke(com.braze.models.dust.c.a.a(jSONObject));
                return;
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, b, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new W(str2, 12), 8, (Object) null);
                return;
            }
        }
        BrazeLogger.brazelog$default(brazeLogger, str3, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(5, str, str2), 14, (Object) null);
    }

    public static final String a(String str, String str2) {
        return "Got event '" + str + "' and data: '" + str2 + '\'';
    }

    public static final String a(JSONObject jSONObject) {
        return "Parsed dust message json to:\n" + JsonUtils.getPrettyPrintedString(jSONObject);
    }
}
