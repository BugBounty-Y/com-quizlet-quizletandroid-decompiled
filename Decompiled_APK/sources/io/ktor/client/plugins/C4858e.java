package io.ktor.client.plugins;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: io.ktor.client.plugins.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4858e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public io.ktor.client.statement.b j;
    public int k;
    public int l;
    public /* synthetic */ Object m;

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4858e c4858e = new C4858e(2, hVar);
        c4858e.m = obj;
        return c4858e;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4858e) create((io.ktor.client.statement.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Can't wrap try/catch for region: R(9:0|2|(1:(1:(8:6|54|7|30|34|(2:39|(1:(1:48)(1:47))(1:43))(1:38)|49|50)(2:9|10))(1:11))(2:12|(2:14|15)(4:16|(2:18|(3:21|(1:24)|28))|51|52))|25|56|26|(6:29|30|34|(2:39|(1:(2:45|48)(0))(0))(0)|49|50)|28|(1:(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00cc, code lost:
    
        r0 = r1;
        r3 = r4;
        r1 = r11;
     */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00d5 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00f7  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 295
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.C4858e.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
