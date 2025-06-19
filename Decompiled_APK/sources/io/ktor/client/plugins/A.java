package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7;
import com.google.android.gms.internal.mlkit_vision_barcode.Z6;
import com.google.android.gms.internal.mlkit_vision_barcode.t7;
import java.io.Serializable;
import java.nio.charset.Charset;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* loaded from: classes3.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.e {
    public int j;
    public /* synthetic */ io.ktor.client.statement.b k;
    public /* synthetic */ io.ktor.utils.io.n l;
    public /* synthetic */ io.ktor.util.reflect.a m;
    public final /* synthetic */ Charset n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(Charset charset, kotlin.coroutines.h hVar) {
        super(5, hVar);
        this.n = charset;
    }

    @Override // kotlin.jvm.functions.e
    public final Object c(Object obj, Object obj2, Object obj3, Object obj4, Serializable serializable) {
        A a = new A(this.n, (kotlin.coroutines.h) serializable);
        a.k = (io.ktor.client.statement.b) obj2;
        a.l = (io.ktor.utils.io.n) obj3;
        a.m = (io.ktor.util.reflect.a) obj4;
        return a.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        io.ktor.client.statement.b bVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            io.ktor.client.statement.b bVar2 = this.k;
            io.ktor.utils.io.n nVar = this.l;
            if (!this.m.a.equals(kotlin.jvm.internal.K.a(String.class))) {
                return null;
            }
            this.k = bVar2;
            this.l = null;
            this.j = 1;
            Object objL = AbstractC3234p7.l(nVar, this);
            if (objL == aVar) {
                return aVar;
            }
            bVar = bVar2;
            obj = objL;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            bVar = this.k;
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        kotlinx.io.i iVar = (kotlinx.io.i) obj;
        io.ktor.client.call.b bVarB = bVar.b();
        org.slf4j.b bVar3 = C.a;
        Charset charset = Z6.b(bVarB.d());
        if (charset == null) {
            charset = this.n;
        }
        C.a.n("Reading response body for " + bVarB.c().i() + " as String with charset " + charset);
        if ((1 & 2) != 0) {
            charset = Charsets.UTF_8;
        }
        Intrinsics.checkNotNullParameter(iVar, "<this>");
        Intrinsics.checkNotNullParameter(charset, "charset");
        return Intrinsics.b(charset, Charsets.UTF_8) ? kotlinx.io.j.f(iVar) : t7.d(charset.newDecoder(), iVar);
    }
}
