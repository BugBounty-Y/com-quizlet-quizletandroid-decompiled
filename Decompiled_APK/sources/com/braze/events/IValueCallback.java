package com.braze.events;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public interface IValueCallback<T> {
    default void onError() {
    }

    void onSuccess(T t);
}
