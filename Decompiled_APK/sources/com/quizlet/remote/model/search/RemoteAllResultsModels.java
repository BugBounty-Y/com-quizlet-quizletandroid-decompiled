package com.quizlet.remote.model.search;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.qclass.RemoteClass;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.term.RemoteTerm;
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
public final class RemoteAllResultsModels extends ApiResponse {
    public final List d;
    public final List e;
    public final List f;
    public final List g;
    public final List h;
    public final List i;
    public final List j;

    public RemoteAllResultsModels(@InterfaceC4853h(name = AssociationNames.CLASS) List<RemoteClass> list, @InterfaceC4853h(name = "set") List<RemoteSet> list2, @InterfaceC4853h(name = "textbook") List<RemoteTextbook> list3, @InterfaceC4853h(name = "explanationQuestion") List<RemoteQuestion> list4, @InterfaceC4853h(name = "user") List<RemoteUser> list5, @InterfaceC4853h(name = "term") List<RemoteTerm> list6, @InterfaceC4853h(name = "socialProof") List<RemoteSearchSocialSignalForSets> list7) {
        this.d = list;
        this.e = list2;
        this.f = list3;
        this.g = list4;
        this.h = list5;
        this.i = list6;
        this.j = list7;
    }

    @NotNull
    public final RemoteAllResultsModels copy(@InterfaceC4853h(name = AssociationNames.CLASS) List<RemoteClass> list, @InterfaceC4853h(name = "set") List<RemoteSet> list2, @InterfaceC4853h(name = "textbook") List<RemoteTextbook> list3, @InterfaceC4853h(name = "explanationQuestion") List<RemoteQuestion> list4, @InterfaceC4853h(name = "user") List<RemoteUser> list5, @InterfaceC4853h(name = "term") List<RemoteTerm> list6, @InterfaceC4853h(name = "socialProof") List<RemoteSearchSocialSignalForSets> list7) {
        return new RemoteAllResultsModels(list, list2, list3, list4, list5, list6, list7);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteAllResultsModels)) {
            return false;
        }
        RemoteAllResultsModels remoteAllResultsModels = (RemoteAllResultsModels) obj;
        return Intrinsics.b(this.d, remoteAllResultsModels.d) && Intrinsics.b(this.e, remoteAllResultsModels.e) && Intrinsics.b(this.f, remoteAllResultsModels.f) && Intrinsics.b(this.g, remoteAllResultsModels.g) && Intrinsics.b(this.h, remoteAllResultsModels.h) && Intrinsics.b(this.i, remoteAllResultsModels.i) && Intrinsics.b(this.j, remoteAllResultsModels.j);
    }

    public final int hashCode() {
        List list = this.d;
        int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
        List list2 = this.e;
        int iHashCode2 = (iHashCode + (list2 == null ? 0 : list2.hashCode())) * 31;
        List list3 = this.f;
        int iHashCode3 = (iHashCode2 + (list3 == null ? 0 : list3.hashCode())) * 31;
        List list4 = this.g;
        int iHashCode4 = (iHashCode3 + (list4 == null ? 0 : list4.hashCode())) * 31;
        List list5 = this.h;
        int iHashCode5 = (iHashCode4 + (list5 == null ? 0 : list5.hashCode())) * 31;
        List list6 = this.i;
        int iHashCode6 = (iHashCode5 + (list6 == null ? 0 : list6.hashCode())) * 31;
        List list7 = this.j;
        return iHashCode6 + (list7 != null ? list7.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteAllResultsModels(classes=");
        sb.append(this.d);
        sb.append(", sets=");
        sb.append(this.e);
        sb.append(", textbooks=");
        sb.append(this.f);
        sb.append(", questions=");
        sb.append(this.g);
        sb.append(", users=");
        sb.append(this.h);
        sb.append(", terms=");
        sb.append(this.i);
        sb.append(", socialSignalsForSets=");
        return android.support.v4.media.session.a.n(")", sb, this.j);
    }
}
