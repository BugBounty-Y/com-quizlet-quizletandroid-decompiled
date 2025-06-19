package com.quizlet.features.notes.detail.navigation;

import androidx.compose.animation.d0;
import androidx.navigation.C1290l;
import androidx.navigation.O;
import androidx.navigation.S;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements com.quizlet.ui.compose.navigation.b {
    public final String a;
    public final boolean b;
    public final AddMaterialFolderData c;

    public i(String defaultUuid, boolean z, AddMaterialFolderData addMaterialFolderData) {
        Intrinsics.checkNotNullParameter(defaultUuid, "defaultUuid");
        this.a = defaultUuid;
        this.b = z;
        this.c = addMaterialFolderData;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        final int i = 0;
        final int i2 = 1;
        final int i3 = 2;
        final int i4 = 3;
        final int i5 = 4;
        return B.j(D1.b("uuid", new Function1(this) { // from class: com.quizlet.features.notes.detail.navigation.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = true;
                        this.b.getClass();
                        navArgument.a(null);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        this.b.getClass();
                        navArgument.a(Boolean.FALSE);
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(AddMaterialFolderData.class));
                        navArgument.a.a = true;
                        navArgument.a(this.b.c);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.b));
                        break;
                }
                return Unit.a;
            }
        }), D1.b("newOutlineId", new Function1(this) { // from class: com.quizlet.features.notes.detail.navigation.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i2) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = true;
                        this.b.getClass();
                        navArgument.a(null);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        this.b.getClass();
                        navArgument.a(Boolean.FALSE);
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(AddMaterialFolderData.class));
                        navArgument.a.a = true;
                        navArgument.a(this.b.c);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.b));
                        break;
                }
                return Unit.a;
            }
        }), D1.b("fetch_from_cache", new Function1(this) { // from class: com.quizlet.features.notes.detail.navigation.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i3) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = true;
                        this.b.getClass();
                        navArgument.a(null);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        this.b.getClass();
                        navArgument.a(Boolean.FALSE);
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(AddMaterialFolderData.class));
                        navArgument.a.a = true;
                        navArgument.a(this.b.c);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.b));
                        break;
                }
                return Unit.a;
            }
        }), D1.b("addMaterialFolderData", new Function1(this) { // from class: com.quizlet.features.notes.detail.navigation.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i4) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = true;
                        this.b.getClass();
                        navArgument.a(null);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        this.b.getClass();
                        navArgument.a(Boolean.FALSE);
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(AddMaterialFolderData.class));
                        navArgument.a.a = true;
                        navArgument.a(this.b.c);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.b));
                        break;
                }
                return Unit.a;
            }
        }), D1.b("displayFlashcardsOnly", new Function1(this) { // from class: com.quizlet.features.notes.detail.navigation.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i5) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = true;
                        this.b.getClass();
                        navArgument.a(null);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        this.b.getClass();
                        navArgument.a(Boolean.FALSE);
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(AddMaterialFolderData.class));
                        navArgument.a.a = true;
                        navArgument.a(this.b.c);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.b));
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
        return "magic_notes";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a.equals(iVar.a) && this.b == iVar.b && Intrinsics.b(this.c, iVar.c);
    }

    public final int hashCode() {
        int iG = d0.g(d0.g(this.a.hashCode() * 961, 31, false), 31, this.b);
        AddMaterialFolderData addMaterialFolderData = this.c;
        return iG + (addMaterialFolderData != null ? addMaterialFolderData.hashCode() : 0);
    }

    public final String toString() {
        return "MagicNotes(defaultUuid=" + this.a + ", defaultNewOutlineId=null, defaultFetchFromCache=false, defaultDisplayFlashcardsOnly=" + this.b + ", defaultAddMaterialFolderData=" + this.c + ")";
    }
}
