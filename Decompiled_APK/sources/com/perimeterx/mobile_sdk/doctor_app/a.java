package com.perimeterx.mobile_sdk.doctor_app;

import com.google.android.gms.internal.ads.C1721Kc;
import com.perimeterx.mobile_sdk.api_data.j;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class a extends i implements Function2 {
    public final /* synthetic */ int j;
    public int k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ Object m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(Object obj, Object obj2, h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.l = obj;
        this.m = obj2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        switch (this.j) {
            case 0:
                return new a((C1721Kc) this.l, (com.braze.triggers.managers.h) this.m, hVar, 0);
            default:
                return new a((com.perimeterx.mobile_sdk.session.d) this.l, (j) this.m, hVar, 1);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        h hVar = (h) obj2;
        switch (this.j) {
            case 0:
                return new a((C1721Kc) this.l, (com.braze.triggers.managers.h) this.m, hVar, 0).invokeSuspend(Unit.a);
            default:
                return new a((com.perimeterx.mobile_sdk.session.d) this.l, (j) this.m, hVar, 1).invokeSuspend(Unit.a);
        }
    }

    /* JADX WARN: Can't wrap try/catch for region: R(9:17|55|(1:(1:(3:21|22|(6:39|63|40|41|51|52)(2:49|50))(2:23|24))(2:25|26))(3:27|28|(2:30|66))|31|61|32|35|(2:37|67)|(0)(0)) */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0087, code lost:
    
        r2 = null;
     */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0098 A[Catch: Exception -> 0x00df, TRY_LEAVE, TryCatch #0 {Exception -> 0x00df, blocks: (B:21:0x0041, B:39:0x0098, B:41:0x00cb, B:47:0x00d3, B:48:0x00d6, B:49:0x00d7, B:50:0x00de, B:25:0x004c, B:31:0x0073, B:35:0x0088, B:28:0x0054, B:45:0x00d1, B:40:0x00c8), top: B:55:0x003b, inners: #1, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00d7 A[Catch: Exception -> 0x00df, TryCatch #0 {Exception -> 0x00df, blocks: (B:21:0x0041, B:39:0x0098, B:41:0x00cb, B:47:0x00d3, B:48:0x00d6, B:49:0x00d7, B:50:0x00de, B:25:0x004c, B:31:0x0073, B:35:0x0088, B:28:0x0054, B:45:0x00d1, B:40:0x00c8), top: B:55:0x003b, inners: #1, #4 }] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 238
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.doctor_app.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
