package com.quizlet.remote.model.search;

import com.quizlet.remote.model.school.RemoteSchool;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteAllResultsAssociationModels {
    public final List a;
    public final List b;
    public final List c;

    public RemoteAllResultsAssociationModels(@InterfaceC4853h(name = "school") List<RemoteSchool> list, @InterfaceC4853h(name = "user") List<RemoteUser> list2, @InterfaceC4853h(name = "set") List<RemoteSet> list3) {
        this.a = list;
        this.b = list2;
        this.c = list3;
    }

    @NotNull
    public final RemoteAllResultsAssociationModels copy(@InterfaceC4853h(name = "school") List<RemoteSchool> list, @InterfaceC4853h(name = "user") List<RemoteUser> list2, @InterfaceC4853h(name = "set") List<RemoteSet> list3) {
        return new RemoteAllResultsAssociationModels(list, list2, list3);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteAllResultsAssociationModels)) {
            return false;
        }
        RemoteAllResultsAssociationModels remoteAllResultsAssociationModels = (RemoteAllResultsAssociationModels) obj;
        return Intrinsics.b(this.a, remoteAllResultsAssociationModels.a) && Intrinsics.b(this.b, remoteAllResultsAssociationModels.b) && Intrinsics.b(this.c, remoteAllResultsAssociationModels.c);
    }

    public final int hashCode() {
        List list = this.a;
        int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
        List list2 = this.b;
        int iHashCode2 = (iHashCode + (list2 == null ? 0 : list2.hashCode())) * 31;
        List list3 = this.c;
        return iHashCode2 + (list3 != null ? list3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteAllResultsAssociationModels(schools=");
        sb.append(this.a);
        sb.append(", setsCreators=");
        sb.append(this.b);
        sb.append(", termSets=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }
}
