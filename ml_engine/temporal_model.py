import torch
import torch.nn as nn

class TemporalRiskLSTM(nn.Module):
    def __init__(self, in_channels=4, hidden_size=16, num_layers=1):
        """
        Input sequence features:
        [time_delta_days, is_vulnerable, cvss_score, patch_delay]
        """
        super(TemporalRiskLSTM, self).__init__()
        self.lstm = nn.LSTM(
            input_size=in_channels,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True
        )
        self.fc = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        """
        x: Shape (batch_size, sequence_length, in_channels)
        """
        # lstm_out: (batch_size, sequence_length, hidden_size)
        # (h_n, c_n): h_n shape (num_layers, batch_size, hidden_size)
        lstm_out, (h_n, c_n) = self.lstm(x)
        
        # Take the hidden state of the last time step
        last_step = lstm_out[:, -1, :]
        
        out = self.fc(last_step)
        temporal_drift_score = self.sigmoid(out)
        return temporal_drift_score
