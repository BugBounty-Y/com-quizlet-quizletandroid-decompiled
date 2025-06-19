package androidx.compose.runtime.saveable;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function0 {
    public final /* synthetic */ b a;
    public final /* synthetic */ l b;
    public final /* synthetic */ i c;
    public final /* synthetic */ String d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object[] f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, l lVar, i iVar, String str, Object obj, Object[] objArr) {
        super(0);
        this.a = bVar;
        this.b = lVar;
        this.c = iVar;
        this.d = str;
        this.e = obj;
        this.f = objArr;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws Throwable {
        boolean z;
        b bVar = this.a;
        i iVar = bVar.b;
        i iVar2 = this.c;
        boolean z2 = true;
        if (iVar != iVar2) {
            bVar.b = iVar2;
            z = true;
        } else {
            z = false;
        }
        String str = bVar.c;
        String str2 = this.d;
        if (Intrinsics.b(str, str2)) {
            z2 = z;
        } else {
            bVar.c = str2;
        }
        bVar.a = this.b;
        bVar.d = this.e;
        bVar.e = this.f;
        h hVar = bVar.f;
        if (hVar != null && z2) {
            ((com.quizlet.data.repository.course.membership.c) hVar).q();
            bVar.f = null;
            bVar.c();
        }
        return Unit.a;
    }
}
