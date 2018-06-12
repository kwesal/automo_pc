`define SRC_INC_PPA_KS
module power_emulator_ip
   (
      input clk, reset_n,
      input s_read, s_write,
      input [3:0] s_addr,
      input [31:0] s_wdata,
      output reg [31:0] s_rdata
   );
   localparam BITS = 'd32; //user accuracy
   localparam CGES = 'd13;
   localparam MAX = $clog2(CGES) + BITS;
   wire [MAX-'d1:0] result;
   wire [MAX-'d1:0] result2;
   wire start, fin;
   reg [31:0] mem [0:15];
   
   //최종 목표 모듈
   TOP #(BITS,CGES)
      U1_TOP
      (
         clk,
         reset_n,
         start,
         fin,
         result
      );
    // 바로 start, 무한
      TOP #(BITS,CGES)
      U2_TOP
      (
         clk,
         reset_n,
         1'b1,
         1'b0,
         result2
      );
    CPA_module #(32) U_CPA(32'd3, 32'd4, result_cpa);
    wire [35:0] vs;
    wire [35:0] vc;
    adder_tree_module #(32,13,36,7) U_tree(clk, reset_n, 1'd1, 12'hFFF, vs, vc);

    initial begin
      mem[0] = 32'd0;
      mem[1] = 32'd1;
      mem[2] = 32'd2;
      mem[3] = 32'd3;
      mem[4] = 32'd4;
      mem[5] = 32'd5;
      mem[6] = 32'd6;
      mem[7] = 32'd7;
      mem[8] = 32'd8;
      mem[9] = 32'd9;
      mem[10] = 32'd10;
      mem[11] = 32'd11;
      mem[12] = 32'd12;
      mem[13] = 32'd13;
      mem[14] = 32'd14;
      mem[15] = 32'd15;
    end
   
   // Register File Read
   always @(posedge clk) begin
   
      // READ
      if(s_read == 1) begin
        s_rdata <= mem[s_addr];
      end
      
      // WRITE
      if(s_write == 1) begin
		mem[s_addr] <= s_wdata;
      end
      //mem[2] <= 32'hFFFFFFFF;
      //mem[3] <= 32'h11111111;
      
      //최종 목표
      mem[1] <= result[31:0];
      mem[2] <= {28'd0, result[35:32]};

      //무한 
      mem[3] <= result2[31:0];
      mem[4] <= {28'd0, result2[35:32]};
      
      //기본 덧셈
      mem[5] <= 32'd2 + 32'd4;
      mem[6] = 32'd2 + 32'd4;

      //CPA
      mem[7] <= result_cpa;
      mem[8] = result_cpa;

      //adder tree
		mem[9] <= vs[31:0];
      mem[10] <= {28'd0, vs[35:32]};
      mem[11] <= vc[31:0];
      mem[12] <= {28'd0, vc[35:32]};
      
   end
    assign start = mem[0][0];
    assign fin   = mem[0][1];
  
endmodule