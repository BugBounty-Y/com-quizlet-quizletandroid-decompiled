package com.quizlet.features.infra.folder.create;

import androidx.lifecycle.p0;
import com.quizlet.features.setpage.termlist.TermListComposeFragment;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements kotlin.jvm.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        Object obj5 = this.b;
        switch (this.a) {
            case 0:
                String title = (String) obj;
                String description = (String) obj2;
                long jLongValue = ((Long) obj3).longValue();
                long jLongValue2 = ((Long) obj4).longValue();
                String str = CreateFolderModalFragment.w;
                Intrinsics.checkNotNullParameter(title, "folderTitle");
                Intrinsics.checkNotNullParameter(description, "folderDescription");
                com.quizlet.features.infra.folder.create.viewmodel.b bVar = (com.quizlet.features.infra.folder.create.viewmodel.b) ((CreateFolderModalFragment) obj5).v.getValue();
                bVar.getClass();
                Intrinsics.checkNotNullParameter(title, "title");
                Intrinsics.checkNotNullParameter(description, "description");
                E.A(p0.j(bVar), null, null, new com.quizlet.features.infra.folder.create.viewmodel.a(bVar, title, description, jLongValue, jLongValue2, null), 3);
                break;
            case 1:
                long jLongValue3 = ((Long) obj).longValue();
                boolean zBooleanValue = ((Boolean) obj2).booleanValue();
                String str2 = TermListComposeFragment.m;
                ((TermListComposeFragment) obj5).U().B(new com.quizlet.features.setpage.termlist.data.c(jLongValue3, (String) obj3, (String) obj4, !zBooleanValue));
                break;
            default:
                long jLongValue4 = ((Long) obj).longValue();
                String email = (String) obj2;
                String password = (String) obj3;
                boolean zBooleanValue2 = ((Boolean) obj4).booleanValue();
                Intrinsics.checkNotNullParameter(email, "email");
                Intrinsics.checkNotNullParameter(password, "password");
                ((Function1) obj5).invoke(new com.quizlet.login.signup.data.c(jLongValue4, email, password, zBooleanValue2));
                break;
        }
        return Unit.a;
    }
}
