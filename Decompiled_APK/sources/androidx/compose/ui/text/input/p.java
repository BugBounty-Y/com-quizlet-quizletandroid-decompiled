package androidx.compose.ui.text.input;

import android.os.Bundle;
import android.os.Handler;
import android.view.KeyEvent;
import android.view.inputmethod.CompletionInfo;
import android.view.inputmethod.CorrectionInfo;
import android.view.inputmethod.ExtractedText;
import android.view.inputmethod.ExtractedTextRequest;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputContentInfo;
import androidx.compose.runtime.C0775b0;

/* loaded from: classes.dex */
public class p implements InputConnection {
    public final C0775b0 a;
    public androidx.compose.foundation.text.input.internal.D b;

    public p(androidx.compose.foundation.text.input.internal.D d, C0775b0 c0775b0) {
        this.a = c0775b0;
        this.b = d;
    }

    public final void a(androidx.compose.foundation.text.input.internal.D d) {
        d.closeConnection();
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean beginBatchEdit() {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.beginBatchEdit();
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean clearMetaKeyStates(int i) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.clearMetaKeyStates(i);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final void closeConnection() {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            if (d != null) {
                a(d);
                this.b = null;
            }
            this.a.invoke(this);
        }
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean commitCompletion(CompletionInfo completionInfo) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.commitCompletion(completionInfo);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean commitContent(InputContentInfo inputContentInfo, int i, Bundle bundle) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.commitContent(inputContentInfo, i, bundle);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean commitCorrection(CorrectionInfo correctionInfo) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.commitCorrection(correctionInfo);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean commitText(CharSequence charSequence, int i) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.commitText(charSequence, i);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean deleteSurroundingText(int i, int i2) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.deleteSurroundingText(i, i2);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean deleteSurroundingTextInCodePoints(int i, int i2) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.deleteSurroundingTextInCodePoints(i, i2);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean endBatchEdit() {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.b();
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean finishComposingText() {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.finishComposingText();
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final int getCursorCapsMode(int i) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.getCursorCapsMode(i);
        }
        return 0;
    }

    @Override // android.view.inputmethod.InputConnection
    public final ExtractedText getExtractedText(ExtractedTextRequest extractedTextRequest, int i) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.getExtractedText(extractedTextRequest, i);
        }
        return null;
    }

    @Override // android.view.inputmethod.InputConnection
    public final Handler getHandler() {
        return null;
    }

    @Override // android.view.inputmethod.InputConnection
    public final CharSequence getSelectedText(int i) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.getSelectedText(i);
        }
        return null;
    }

    @Override // android.view.inputmethod.InputConnection
    public final CharSequence getTextAfterCursor(int i, int i2) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.getTextAfterCursor(i, i2);
        }
        return null;
    }

    @Override // android.view.inputmethod.InputConnection
    public final CharSequence getTextBeforeCursor(int i, int i2) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.getTextBeforeCursor(i, i2);
        }
        return null;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean performContextMenuAction(int i) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.performContextMenuAction(i);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean performEditorAction(int i) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.performEditorAction(i);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean performPrivateCommand(String str, Bundle bundle) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.performPrivateCommand(str, bundle);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean reportFullscreenMode(boolean z) {
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean requestCursorUpdates(int i) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.requestCursorUpdates(i);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean sendKeyEvent(KeyEvent keyEvent) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.sendKeyEvent(keyEvent);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean setComposingRegion(int i, int i2) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.setComposingRegion(i, i2);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean setComposingText(CharSequence charSequence, int i) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.setComposingText(charSequence, i);
        }
        return false;
    }

    @Override // android.view.inputmethod.InputConnection
    public final boolean setSelection(int i, int i2) {
        androidx.compose.foundation.text.input.internal.D d = this.b;
        if (d != null) {
            return d.setSelection(i, i2);
        }
        return false;
    }
}
