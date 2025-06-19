package com.quizlet.explanations.questiondetail.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.A1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.l7;
import com.quizlet.features.folders.data.C4298o;
import com.quizlet.features.folders.data.C4317y;
import com.quizlet.generated.enums.y1;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class l implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ l(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                l7.b(this.b, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 1:
                com.quizlet.features.folders.addtofolder.data.s item = (com.quizlet.features.folders.addtofolder.data.s) obj;
                int iIntValue = ((Integer) obj2).intValue();
                Intrinsics.checkNotNullParameter(item, "item");
                this.b.invoke(new com.quizlet.features.folders.addtofolder.data.l(item, iIntValue));
                break;
            case 2:
                ((Long) obj).getClass();
                List tags = (List) obj2;
                Intrinsics.checkNotNullParameter(tags, "tags");
                this.b.invoke(new C4317y(tags));
                break;
            case 3:
                String materialId = (String) obj;
                y1 studyMaterialType = (y1) obj2;
                Intrinsics.checkNotNullParameter(materialId, "materialId");
                Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
                this.b.invoke(new C4298o(materialId, studyMaterialType));
                break;
            case 4:
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f data = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f) obj;
                int iIntValue2 = ((Integer) obj2).intValue();
                Intrinsics.checkNotNullParameter(data, "data");
                this.b.invoke(new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.j(data, iIntValue2));
                break;
            case 5:
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f data2 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f) obj;
                long jLongValue = ((Long) obj2).longValue();
                Intrinsics.checkNotNullParameter(data2, "data");
                this.b.invoke(new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.k(data2, jLongValue));
                break;
            case 6:
                ((Integer) obj2).getClass();
                A1.a(this.b, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 7:
                int iIntValue3 = ((Integer) obj).intValue();
                String id = (String) obj2;
                Intrinsics.checkNotNullParameter(id, "id");
                this.b.invoke(new com.quizlet.features.practicetest.results.data.j(iIntValue3, id));
                break;
            default:
                String email = (String) obj;
                String password = (String) obj2;
                Intrinsics.checkNotNullParameter(email, "email");
                Intrinsics.checkNotNullParameter(password, "password");
                this.b.invoke(new com.quizlet.login.parentemail.data.b(email, password));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ l(Function1 function1, int i, int i2) {
        this.a = i2;
        this.b = function1;
    }
}
