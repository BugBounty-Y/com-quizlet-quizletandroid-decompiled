package io.ktor.utils.io.jvm.javaio;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.u7;
import io.ktor.utils.io.x;
import java.io.EOFException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public final /* synthetic */ d j;
    public final /* synthetic */ int k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(d dVar, int i, h hVar) {
        super(2, hVar);
        this.j = dVar;
        this.k = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        d dVar;
        kotlinx.io.b bVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        long jA = 0;
        while (true) {
            dVar = this.j;
            long jC = u7.c(dVar.e);
            long j = this.k;
            bVar = dVar.b;
            if (jC >= j || jA < 0) {
                break;
            }
            try {
                jA = bVar.A(dVar.e, Long.MAX_VALUE);
            } catch (EOFException unused) {
                jA = -1;
            }
        }
        if (jA == -1) {
            bVar.close();
            dVar.f.k0();
            dVar.d = new x(null);
        }
        return Unit.a;
    }
}
