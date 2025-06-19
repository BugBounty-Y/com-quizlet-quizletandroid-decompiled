package com.quizlet.features.notes.upload.navigation;

import androidx.navigation.B;
import androidx.navigation.H;
import androidx.navigation.r;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.quizlet.data.model.U0;
import com.quizlet.data.model.m2;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b extends C4956o implements kotlin.jvm.functions.d {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        switch (this.a) {
            case 0:
                Boolean bool = (Boolean) obj;
                bool.getClass();
                m2 source = (m2) obj2;
                String initialText = (String) obj3;
                AddMaterialFolderData addMaterialFolderData = (AddMaterialFolderData) obj4;
                Intrinsics.checkNotNullParameter(source, "p1");
                Intrinsics.checkNotNullParameter(initialText, "p2");
                H h = (H) this.receiver;
                Intrinsics.checkNotNullParameter(h, "<this>");
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(initialText, "initialText");
                B bK = h.b.h().k("pasteText");
                if (bK != null) {
                    h.b(bK.b.c, AbstractC3206m6.a(new Pair("isPrivate", bool), new Pair("source", source), new Pair("text", initialText), new Pair("addMaterialFolderData", addMaterialFolderData)), null);
                } else {
                    r.d(h, "pasteText");
                }
                break;
            case 1:
                String p0 = (String) obj;
                String p1 = (String) obj2;
                U0 p2 = (U0) obj3;
                Intrinsics.checkNotNullParameter(p0, "p0");
                Intrinsics.checkNotNullParameter(p1, "p1");
                Intrinsics.checkNotNullParameter(p2, "p2");
                com.quizlet.features.practicetest.navigation.c.e((H) this.receiver, p0, p1, p2, (String) obj4);
                break;
            default:
                String p02 = (String) obj;
                String p12 = (String) obj2;
                U0 p22 = (U0) obj3;
                Intrinsics.checkNotNullParameter(p02, "p0");
                Intrinsics.checkNotNullParameter(p12, "p1");
                Intrinsics.checkNotNullParameter(p22, "p2");
                com.quizlet.features.practicetest.navigation.c.e((H) this.receiver, p02, p12, p22, (String) obj4);
                break;
        }
        return Unit.a;
    }
}
