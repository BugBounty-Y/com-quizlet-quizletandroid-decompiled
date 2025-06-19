package com.quizlet.features.universaluploadflow.pastetext.data;

import com.comscore.android.ConnectivityType;

/* loaded from: classes3.dex */
public final class m implements p {
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        ((m) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return Integer.hashCode(100) + (Integer.hashCode(ConnectivityType.UNKNOWN) * 31);
    }

    public final String toString() {
        return "Content(text=, maximumCharacter=40000, minimumCharacter=100)";
    }
}
