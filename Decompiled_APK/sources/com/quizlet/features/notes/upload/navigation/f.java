package com.quizlet.features.notes.upload.navigation;

import android.net.Uri;
import androidx.navigation.C1290l;
import androidx.navigation.M;
import androidx.navigation.N;
import androidx.navigation.O;
import androidx.navigation.S;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.data.model.m2;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import java.util.Arrays;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements com.quizlet.ui.compose.navigation.b {
    public final m2 a;
    public final String b;
    public final Uri[] c;
    public final AddMaterialFolderData d;

    public f(m2 source, String str, Uri[] uriArr, AddMaterialFolderData addMaterialFolderData) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
        this.b = str;
        this.c = uriArr;
        this.d = addMaterialFolderData;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        final int i = 0;
        final int i2 = 1;
        final int i3 = 2;
        final int i4 = 3;
        return B.j(D1.b("source", new Function1(this) { // from class: com.quizlet.features.notes.upload.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new M(m2.class));
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(new N(Uri.class));
                        navArgument.a(this.b.c);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(new O(AddMaterialFolderData.class));
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        }), D1.b("text", new Function1(this) { // from class: com.quizlet.features.notes.upload.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i2) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new M(m2.class));
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(new N(Uri.class));
                        navArgument.a(this.b.c);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(new O(AddMaterialFolderData.class));
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        }), D1.b("uris", new Function1(this) { // from class: com.quizlet.features.notes.upload.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i3) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new M(m2.class));
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(new N(Uri.class));
                        navArgument.a(this.b.c);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(new O(AddMaterialFolderData.class));
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        }), D1.b("addMaterialFolderData", new Function1(this) { // from class: com.quizlet.features.notes.upload.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i4) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new M(m2.class));
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(new N(Uri.class));
                        navArgument.a(this.b.c);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(new O(AddMaterialFolderData.class));
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        }));
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "upload";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b) && Intrinsics.b(this.c, fVar.c) && Intrinsics.b(this.d, fVar.d);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        Uri[] uriArr = this.c;
        int iHashCode3 = (iHashCode2 + (uriArr == null ? 0 : Arrays.hashCode(uriArr))) * 31;
        AddMaterialFolderData addMaterialFolderData = this.d;
        return iHashCode3 + (addMaterialFolderData != null ? addMaterialFolderData.hashCode() : 0);
    }

    public final String toString() {
        return "Upload(source=" + this.a + ", initialText=" + this.b + ", initialUris=" + Arrays.toString(this.c) + ", addMaterialFolderData=" + this.d + ")";
    }
}
