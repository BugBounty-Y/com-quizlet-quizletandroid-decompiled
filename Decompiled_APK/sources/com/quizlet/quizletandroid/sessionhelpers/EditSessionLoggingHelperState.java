package com.quizlet.quizletandroid.sessionhelpers;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.onetrust.otpublishers.headless.UI.DataModels.f;
import com.quizlet.eventlogger.model.EditSessionsLog;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class EditSessionLoggingHelperState implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<EditSessionLoggingHelperState> CREATOR = new f(11);
    public final HashMap a;
    public final ArrayList b;
    public final EditSessionsLog c;
    public b d;
    public Date e;
    public SavedAction f;

    public EditSessionLoggingHelperState(HashMap mTermActionsTracker, ArrayList mActionsTracker, EditSessionsLog mEditSession, b bVar, Date date, SavedAction savedAction) {
        Intrinsics.checkNotNullParameter(mTermActionsTracker, "mTermActionsTracker");
        Intrinsics.checkNotNullParameter(mActionsTracker, "mActionsTracker");
        Intrinsics.checkNotNullParameter(mEditSession, "mEditSession");
        this.a = mTermActionsTracker;
        this.b = mActionsTracker;
        this.c = mEditSession;
        this.d = bVar;
        this.e = date;
        this.f = savedAction;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof EditSessionLoggingHelperState)) {
            return false;
        }
        EditSessionLoggingHelperState editSessionLoggingHelperState = (EditSessionLoggingHelperState) obj;
        return this.a.equals(editSessionLoggingHelperState.a) && this.b.equals(editSessionLoggingHelperState.b) && Intrinsics.b(this.c, editSessionLoggingHelperState.c) && this.d == editSessionLoggingHelperState.d && Intrinsics.b(this.e, editSessionLoggingHelperState.e) && Intrinsics.b(this.f, editSessionLoggingHelperState.f);
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + d0.h(this.b, this.a.hashCode() * 31, 31)) * 31;
        b bVar = this.d;
        int iHashCode2 = (iHashCode + (bVar == null ? 0 : bVar.hashCode())) * 31;
        Date date = this.e;
        int iHashCode3 = (iHashCode2 + (date == null ? 0 : date.hashCode())) * 31;
        SavedAction savedAction = this.f;
        return iHashCode3 + (savedAction != null ? savedAction.hashCode() : 0);
    }

    public final String toString() {
        return "EditSessionLoggingHelperState(mTermActionsTracker=" + this.a + ", mActionsTracker=" + this.b + ", mEditSession=" + this.c + ", mCurrentlyFocused=" + this.d + ", mActionTimeStart=" + this.e + ", mLastAction=" + this.f + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        HashMap map = this.a;
        dest.writeInt(map.size());
        for (Map.Entry entry : map.entrySet()) {
            dest.writeString((String) entry.getKey());
            dest.writeParcelable((Parcelable) entry.getValue(), i);
        }
        ArrayList arrayList = this.b;
        dest.writeInt(arrayList.size());
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            dest.writeParcelable((Parcelable) it2.next(), i);
        }
        dest.writeParcelable(this.c, i);
        b bVar = this.d;
        if (bVar == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeString(bVar.name());
        }
        dest.writeSerializable(this.e);
        SavedAction savedAction = this.f;
        if (savedAction == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            savedAction.writeToParcel(dest, i);
        }
    }
}
