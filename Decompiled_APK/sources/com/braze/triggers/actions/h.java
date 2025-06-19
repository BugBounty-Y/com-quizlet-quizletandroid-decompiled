package com.braze.triggers.actions;

import java.util.HashMap;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class h extends g {
    public HashMap f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(JSONObject json) {
        super(json);
        Intrinsics.checkNotNullParameter(json, "json");
        this.f = new LinkedHashMap();
    }
}
