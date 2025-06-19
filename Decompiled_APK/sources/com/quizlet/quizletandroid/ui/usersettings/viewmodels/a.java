package com.quizlet.quizletandroid.ui.usersettings.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ c l;
    public final /* synthetic */ String m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, String str, String str2, h hVar) {
        super(2, hVar);
        this.l = cVar;
        this.m = str;
        this.n = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        a aVar = new a(this.l, this.m, this.n, hVar);
        aVar.k = obj;
        return aVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((LoggedInUserStatus) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objC;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        c cVar = this.l;
        String str = this.m;
        if (i == 0) {
            Z.e(obj);
            DBUser currentUser = ((LoggedInUserStatus) this.k).getCurrentUser();
            if (currentUser != null) {
                this.j = 1;
                if (Intrinsics.b(currentUser.getProfileImageId(), str)) {
                    objC = Unit.a;
                } else {
                    currentUser.setProfileImageId(str);
                    io.reactivex.rxjava3.core.i iVarA = cVar.e.a(currentUser);
                    Intrinsics.checkNotNullExpressionValue(iVarA, "saveAndSync(...)");
                    objC = I1.c(iVarA, this);
                    if (objC != obj2) {
                        objC = Unit.a;
                    }
                }
                if (objC == obj2) {
                    return obj2;
                }
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        cVar.f.j(new com.quizlet.quizletandroid.ui.usersettings.data.a(str, this.n));
        return Unit.a;
    }
}
