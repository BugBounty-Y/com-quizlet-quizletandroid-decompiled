package androidx.compose.material3;

import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class M implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.runtime.snapshots.q b;

    public /* synthetic */ M(androidx.compose.runtime.snapshots.q qVar, int i) {
        this.a = i;
        this.b = qVar;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                androidx.compose.foundation.interaction.j jVar = (androidx.compose.foundation.interaction.j) obj;
                boolean z = jVar instanceof androidx.compose.foundation.interaction.h;
                androidx.compose.runtime.snapshots.q qVar = this.b;
                if (z) {
                    qVar.add(jVar);
                } else if (jVar instanceof androidx.compose.foundation.interaction.i) {
                    qVar.remove(((androidx.compose.foundation.interaction.i) jVar).a);
                } else if (jVar instanceof androidx.compose.foundation.interaction.d) {
                    qVar.add(jVar);
                } else if (jVar instanceof androidx.compose.foundation.interaction.e) {
                    qVar.remove(((androidx.compose.foundation.interaction.e) jVar).a);
                } else if (jVar instanceof androidx.compose.foundation.interaction.o) {
                    qVar.add(jVar);
                } else if (jVar instanceof androidx.compose.foundation.interaction.p) {
                    qVar.remove(((androidx.compose.foundation.interaction.p) jVar).a);
                } else if (jVar instanceof androidx.compose.foundation.interaction.n) {
                    qVar.remove(((androidx.compose.foundation.interaction.n) jVar).a);
                }
                break;
            default:
                androidx.compose.foundation.interaction.j jVar2 = (androidx.compose.foundation.interaction.j) obj;
                boolean z2 = jVar2 instanceof androidx.compose.foundation.interaction.h;
                androidx.compose.runtime.snapshots.q qVar2 = this.b;
                if (z2) {
                    qVar2.add(jVar2);
                } else if (jVar2 instanceof androidx.compose.foundation.interaction.i) {
                    qVar2.remove(((androidx.compose.foundation.interaction.i) jVar2).a);
                } else if (jVar2 instanceof androidx.compose.foundation.interaction.d) {
                    qVar2.add(jVar2);
                } else if (jVar2 instanceof androidx.compose.foundation.interaction.e) {
                    qVar2.remove(((androidx.compose.foundation.interaction.e) jVar2).a);
                } else if (jVar2 instanceof androidx.compose.foundation.interaction.o) {
                    qVar2.add(jVar2);
                } else if (jVar2 instanceof androidx.compose.foundation.interaction.p) {
                    qVar2.remove(((androidx.compose.foundation.interaction.p) jVar2).a);
                } else if (jVar2 instanceof androidx.compose.foundation.interaction.n) {
                    qVar2.remove(((androidx.compose.foundation.interaction.n) jVar2).a);
                } else if (jVar2 instanceof androidx.compose.foundation.interaction.b) {
                    qVar2.add(jVar2);
                } else if (jVar2 instanceof androidx.compose.foundation.interaction.c) {
                    qVar2.remove(((androidx.compose.foundation.interaction.c) jVar2).a);
                } else if (jVar2 instanceof androidx.compose.foundation.interaction.a) {
                    qVar2.remove(((androidx.compose.foundation.interaction.a) jVar2).a);
                }
                break;
        }
        return Unit.a;
    }
}
