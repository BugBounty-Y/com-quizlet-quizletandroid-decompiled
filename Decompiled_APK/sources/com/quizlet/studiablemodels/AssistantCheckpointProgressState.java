package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class AssistantCheckpointProgressState implements serialization.f, Parcelable {

    @NotNull
    public static final Parcelable.Creator<AssistantCheckpointProgressState> CREATOR;
    public static final com.quizlet.quizletandroid.ui.profile.data.b b;
    public static final /* synthetic */ AssistantCheckpointProgressState[] c;
    public final String a;

    static {
        AssistantCheckpointProgressState[] assistantCheckpointProgressStateArr = {new AssistantCheckpointProgressState("ROUND_CHECKPOINT", 0, "ROUND_CHECKPOINT"), new AssistantCheckpointProgressState("TASK_COMPLETION_CHECKPOINT", 1, "TASK_COMPLETION_CHECKPOINT"), new AssistantCheckpointProgressState("LEARN_COMPLETION_CHECKPOINT", 2, "LEARN_COMPLETION_CHECKPOINT"), new AssistantCheckpointProgressState("POST_COMPLETION_CHECKPOINT", 3, "POST_COMPLETION_CHECKPOINT")};
        c = assistantCheckpointProgressStateArr;
        AbstractC3328d.f(assistantCheckpointProgressStateArr);
        b = new com.quizlet.quizletandroid.ui.profile.data.b(4);
        CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(24);
    }

    public AssistantCheckpointProgressState(String str, int i, String str2) {
        this.a = str2;
    }

    public static AssistantCheckpointProgressState valueOf(String str) {
        return (AssistantCheckpointProgressState) Enum.valueOf(AssistantCheckpointProgressState.class, str);
    }

    public static AssistantCheckpointProgressState[] values() {
        return (AssistantCheckpointProgressState[]) c.clone();
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(name());
    }
}
