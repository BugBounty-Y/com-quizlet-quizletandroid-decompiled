package com.quizlet.quizletandroid.ui.library;

import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.google.android.gms.internal.mlkit_vision_barcode.U5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3690o5;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.CreatedFolderWithCreator;
import com.quizlet.data.model.User;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.library.data.C4649c;
import com.quizlet.quizletandroid.ui.library.data.C4653g;
import com.quizlet.quizletandroid.ui.library.data.C4654h;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class F extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ c0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        F f = new F(this.k, hVar);
        f.j = obj;
        return f;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((F) create((List) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        com.quizlet.quizletandroid.ui.library.data.J j;
        AbstractC3690o5 c4653g;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        List<CreatedFolderWithCreator> list = (List) this.j;
        c0 c0Var = this.k;
        s0 s0Var = c0Var.t;
        do {
            value = s0Var.getValue();
            j = (com.quizlet.quizletandroid.ui.library.data.J) value;
            if (list.isEmpty()) {
                c4653g = C4654h.a;
            } else {
                Intrinsics.checkNotNullParameter(list, "<this>");
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                for (CreatedFolderWithCreator createdFolderWithCreator : list) {
                    long jA = createdFolderWithCreator.a.a();
                    CreatedFolder createdFolder = createdFolderWithCreator.a;
                    String strG = createdFolder.g();
                    User user = createdFolderWithCreator.b;
                    String str = user != null ? user.b : null;
                    String str2 = str == null ? "" : str;
                    String str3 = user != null ? user.i : null;
                    arrayList.add(new C4649c(new com.quizlet.ui.models.content.carditem.c(user != null ? AbstractC3179j6.b(user) : R.string.empty, jA, strG, str2, str3 == null ? "" : str3, user != null ? user.e : false), U5.c(createdFolder)));
                }
                c4653g = new C4653g(AbstractC3409x1.k(arrayList));
            }
        } while (!s0Var.k(value, com.quizlet.quizletandroid.ui.library.data.J.a(j, null, null, null, c4653g, null, false, false, false, 247)));
        if (!list.isEmpty()) {
            kotlinx.coroutines.E.A(p0.j(c0Var), null, null, new C(c0Var, true, true, null), 3);
        }
        return Unit.a;
    }
}
