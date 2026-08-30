import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv

class HGATModel(nn.Module):
    def __init__(self, in_channels=13, hidden_channels=32, out_channels=1, heads=2):
        super(HGATModel, self).__init__()
        # We use a multi-head Graph Attention Network (GAT)
        self.conv1 = GATConv(in_channels, hidden_channels, heads=heads, concat=True, dropout=0.1)
        self.conv2 = GATConv(hidden_channels * heads, hidden_channels, heads=1, concat=False, dropout=0.1)
        
        # Dense classification layers
        self.fc1 = nn.Linear(hidden_channels, 16)
        self.fc2 = nn.Linear(16, out_channels)
        
        # Weight initialization
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0.0)

    def forward(self, x, edge_index, return_attention=False):
        """
        x: Node feature matrix of shape (num_nodes, 13)
        edge_index: Graph adjacency of shape (2, num_edges)
        """
        # First GAT layer
        if return_attention:
            # GATConv returns (out, (edge_index, att_weights))
            h, (att_edge_index, att_weights) = self.conv1(x, edge_index, return_attention_weights=True)
        else:
            h = self.conv1(x, edge_index)
            
        h = F.elu(h)
        h = F.dropout(h, p=0.1, training=self.training)
        
        # Second GAT layer
        h = self.conv2(h, edge_index)
        h = F.elu(h)
        
        # Fully connected predictor
        out = F.relu(self.fc1(h))
        out = self.fc2(out)
        
        # Sigmoid probability
        prob = torch.sigmoid(out)
        
        if return_attention:
            return prob, att_edge_index, att_weights
        return prob
