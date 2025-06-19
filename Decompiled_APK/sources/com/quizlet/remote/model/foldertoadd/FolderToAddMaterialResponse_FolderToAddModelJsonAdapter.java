package com.quizlet.remote.model.foldertoadd;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.foldertoadd.FolderToAddMaterialResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FolderToAddMaterialResponse_FolderToAddModelJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public volatile Constructor f;

    public FolderToAddMaterialResponse_FolderToAddModelJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "title", "isAlreadyAdded", "subfolders");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "folderName");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Boolean.TYPE, m, "isAlreadyAddedToFolder");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, FolderToAddMaterialResponse.FolderToAddModel.class), m, "subfolders");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        String str = null;
        Boolean bool = null;
        List list = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                l = (Long) this.b.a(reader);
                if (l == null) {
                    throw com.squareup.moshi.internal.b.k("id", "id", reader);
                }
            } else if (iK0 == 1) {
                str = (String) this.c.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("folderName", "title", reader);
                }
            } else if (iK0 == 2) {
                bool = (Boolean) this.d.a(reader);
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.k("isAlreadyAddedToFolder", "isAlreadyAdded", reader);
                }
            } else if (iK0 == 3) {
                list = (List) this.e.a(reader);
                i = -9;
            }
        }
        reader.i();
        if (i == -9) {
            String str2 = str;
            if (l == null) {
                throw com.squareup.moshi.internal.b.e("id", "id", reader);
            }
            Boolean bool2 = bool;
            List list2 = list;
            long jLongValue = l.longValue();
            if (str2 == null) {
                throw com.squareup.moshi.internal.b.e("folderName", "title", reader);
            }
            if (bool2 != null) {
                return new FolderToAddMaterialResponse.FolderToAddModel(jLongValue, str2, bool2.booleanValue(), list2);
            }
            throw com.squareup.moshi.internal.b.e("isAlreadyAddedToFolder", "isAlreadyAdded", reader);
        }
        String str3 = str;
        Boolean bool3 = bool;
        List list3 = list;
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            declaredConstructor = FolderToAddMaterialResponse.FolderToAddModel.class.getDeclaredConstructor(Long.TYPE, String.class, Boolean.TYPE, List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Constructor constructor = declaredConstructor;
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        if (str3 == null) {
            throw com.squareup.moshi.internal.b.e("folderName", "title", reader);
        }
        if (bool3 == null) {
            throw com.squareup.moshi.internal.b.e("isAlreadyAddedToFolder", "isAlreadyAdded", reader);
        }
        Object objNewInstance = constructor.newInstance(l, str3, bool3, list3, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (FolderToAddMaterialResponse.FolderToAddModel) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        FolderToAddMaterialResponse.FolderToAddModel folderToAddModel = (FolderToAddMaterialResponse.FolderToAddModel) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (folderToAddModel == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(folderToAddModel.a));
        writer.l("title");
        this.c.g(writer, folderToAddModel.b);
        writer.l("isAlreadyAdded");
        this.d.g(writer, Boolean.valueOf(folderToAddModel.c));
        writer.l("subfolders");
        this.e.g(writer, folderToAddModel.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(66, "GeneratedJsonAdapter(FolderToAddMaterialResponse.FolderToAddModel)", "toString(...)");
    }
}
