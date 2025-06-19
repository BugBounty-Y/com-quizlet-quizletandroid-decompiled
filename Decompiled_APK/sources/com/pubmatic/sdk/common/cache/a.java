package com.pubmatic.sdk.common.cache;

import android.view.View;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.ui.d;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public class a {

    @NonNull
    private Map<Integer, C0008a> a = Collections.synchronizedMap(new HashMap());

    /* renamed from: com.pubmatic.sdk.common.cache.a$a, reason: collision with other inner class name */
    public static class C0008a {

        @NonNull
        private View a;

        @NonNull
        private d b;
        private com.pubmatic.sdk.common.ui.c c;

        public C0008a(@NonNull View view, @NonNull d dVar) {
            this.a = view;
            this.b = dVar;
        }

        @NonNull
        public View getAdView() {
            return this.a;
        }

        public com.pubmatic.sdk.common.ui.c getBackPressListener() {
            return null;
        }

        @NonNull
        public d getEventListener() {
            return this.b;
        }

        public void setBackPressListener(com.pubmatic.sdk.common.ui.c cVar) {
        }
    }

    public C0008a getStoredAdView(@NonNull Integer num) {
        return this.a.get(num);
    }

    public C0008a popStoredAdView(@NonNull Integer num) {
        return this.a.remove(num);
    }

    public void storeAdView(@NonNull Integer num, @NonNull C0008a c0008a) {
        this.a.put(num, c0008a);
    }
}
