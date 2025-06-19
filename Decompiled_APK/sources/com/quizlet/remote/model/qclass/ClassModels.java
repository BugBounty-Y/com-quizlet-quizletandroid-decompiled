package com.quizlet.remote.model.qclass;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.remote.model.school.RemoteSchool;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ClassModels {
    public final List a;
    public final List b;

    public ClassModels(@InterfaceC4853h(name = AssociationNames.CLASS) List<RemoteClass> list, @InterfaceC4853h(name = "school") List<RemoteSchool> list2) {
        this.a = list;
        this.b = list2;
    }

    @NotNull
    public final ClassModels copy(@InterfaceC4853h(name = AssociationNames.CLASS) List<RemoteClass> list, @InterfaceC4853h(name = "school") List<RemoteSchool> list2) {
        return new ClassModels(list, list2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ClassModels)) {
            return false;
        }
        ClassModels classModels = (ClassModels) obj;
        return Intrinsics.b(this.a, classModels.a) && Intrinsics.b(this.b, classModels.b);
    }

    public final int hashCode() {
        List list = this.a;
        int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
        List list2 = this.b;
        return iHashCode + (list2 != null ? list2.hashCode() : 0);
    }

    public final String toString() {
        return "ClassModels(classList=" + this.a + ", schoolList=" + this.b + ")";
    }
}
