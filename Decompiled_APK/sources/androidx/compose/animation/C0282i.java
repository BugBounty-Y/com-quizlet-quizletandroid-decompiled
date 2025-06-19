package androidx.compose.animation;

import androidx.navigation.C1291m;
import java.util.Map;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.animation.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0282i implements androidx.compose.runtime.G {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ C0282i(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
        this.d = obj3;
    }

    @Override // androidx.compose.runtime.G
    public final void dispose() {
        switch (this.a) {
            case 0:
                androidx.compose.runtime.snapshots.q qVar = (androidx.compose.runtime.snapshots.q) this.c;
                Object obj = this.b;
                qVar.remove(obj);
                ((C0292t) this.d).d.h(obj);
                break;
            case 1:
                androidx.compose.runtime.saveable.f fVar = (androidx.compose.runtime.saveable.f) this.c;
                androidx.collection.I i = fVar.b;
                Object obj2 = this.b;
                Object objH = i.h(obj2);
                androidx.compose.runtime.saveable.i iVar = (androidx.compose.runtime.saveable.i) this.d;
                if (objH == iVar) {
                    Map mapB = iVar.b();
                    boolean zIsEmpty = mapB.isEmpty();
                    Map map = fVar.a;
                    if (!zIsEmpty) {
                        map.put(obj2, mapB);
                        break;
                    } else {
                        map.remove(obj2);
                        break;
                    }
                }
                break;
            case 2:
                androidx.navigation.compose.s sVar = (androidx.navigation.compose.s) this.b;
                C1291m c1291m = (C1291m) this.d;
                sVar.b().c(c1291m);
                ((androidx.compose.runtime.snapshots.q) this.c).remove(c1291m);
                break;
            default:
                ((Function0) this.c).invoke();
                ((androidx.lifecycle.J) this.b).getLifecycle().b((com.quizlet.features.flashcards.screens.d) this.d);
                break;
        }
    }

    public C0282i(androidx.navigation.compose.s sVar, C1291m c1291m, androidx.compose.runtime.snapshots.q qVar) {
        this.a = 2;
        this.b = sVar;
        this.d = c1291m;
        this.c = qVar;
    }
}
